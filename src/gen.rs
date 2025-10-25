use nu_plugin::PluginCommand;
use nu_protocol::{
    record, Category, LabeledError, PipelineData, Signature, Span, SyntaxShape, Type, Value,
};

pub struct GenCommand;

impl GenCommand {
    fn gen(&self, params: rcgen::CertificateParams, span: Span) -> Result<Value, LabeledError> {
        let crt =
            Self::generate_self_signed(params).map_err(|e| LabeledError::new(e.to_string()))?;
        let record = Value::record(
            record!(
                "crt" => Value::string(crt.cert.pem(), span),
                "key" => Value::string(crt.signing_key.serialize_pem(), span),
            ),
            span,
        );
        Ok(record)
    }

    pub fn generate_self_signed(
        params: rcgen::CertificateParams,
    ) -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, rcgen::Error> {
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        Ok(rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        })
    }
}

impl nu_plugin::PluginCommand for GenCommand {
    type Plugin = crate::X509Plugin;

    fn name(&self) -> &str {
        "to x509"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(PluginCommand::name(self))
            .named("name", SyntaxShape::String, "cert name", Some('n'))
            .named("begin_date", SyntaxShape::DateTime, "begin date", Some('b'))
            .named("end_date", SyntaxShape::DateTime, "end date", Some('e'))
            .named("ca_constraint", SyntaxShape::Int, "CA constraint (0 for unconstrained, positive integer for constrained)", Some('c'))
            .named(
                "key_usage",
                SyntaxShape::String,
                "key usage (options: digital_signature, content_commitment, key_encipherment, data_encipherment, key_agreement, key_cert_sign, crl_sign, encipher_only, decipher_only)",
                Some('u')
            )
            .allow_variants_without_examples(true)
            .input_output_types(vec![(
                Type::List(Box::new(Type::String)),
                Type::Record(Box::new([
                    ("crt".to_string(), Type::String),
                    ("key".to_string(), Type::String),
                ])),
            )])
            .category(Category::Experimental)
            .filter()
    }

    fn description(&self) -> &str {
        "Generate a new X509 certificate"
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        _engine: &nu_plugin::EngineInterface,
        call: &nu_plugin::EvaluatedCall,
        input: nu_protocol::PipelineData,
    ) -> Result<nu_protocol::PipelineData, nu_protocol::LabeledError> {
        match input {
            PipelineData::Value(Value::List { vals: list, .. }, pipeline_metadata) => {
                let subject_alt_names: Vec<String> = list
                    .into_iter()
                    .map(|v| v.as_str().unwrap_or_default().to_string())
                    .collect();
                let name = match call.get_flag_value("name") {
                    Some(Value::String { val, .. }) => val,
                    Some(_) | None => "nu_plugin_x509 self signed crt".to_string(),
                };

                let not_before = match call.get_flag_value("begin_date") {
                    Some(Value::Date { val, .. }) => {
                        time::OffsetDateTime::from_unix_timestamp(val.timestamp())
                            .map_err(|e| LabeledError::new(e.to_string()))?
                    }
                    Some(_) | None => rcgen::date_time_ymd(1975, 01, 01),
                };

                let not_after = match call.get_flag_value("end_date") {
                    Some(Value::Date { val, .. }) => {
                        time::OffsetDateTime::from_unix_timestamp(val.timestamp())
                            .map_err(|e| LabeledError::new(e.to_string()))?
                    }
                    Some(_) | None => rcgen::date_time_ymd(4096, 01, 01),
                };

                let ca_constraint = match call.get_flag_value("ca_constraint") {
                    Some(Value::Int { val, .. }) => val,
                    Some(_) | None => -1,
                };

                let key_usage = match call.get_flag_value("key_usage") {
                    Some(Value::String { val, .. }) => val,
                    Some(_) | None => "".to_string(),
                };

                let mut params = rcgen::CertificateParams::new(subject_alt_names)
                    .map_err(|e| LabeledError::new(e.to_string()))?;

                // set params
                let mut distinguished_name = rcgen::DistinguishedName::new();
                distinguished_name.push(rcgen::DnType::CommonName, name);
                params.distinguished_name = distinguished_name;
                params.not_before = not_before;
                params.not_after = not_after;
                if ca_constraint == 0 {
                    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                } else if ca_constraint > 0 {
                    params.is_ca =
                        rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(ca_constraint as u8));
                }
                params.key_usages = key_usage
                    .split(',')
                    .map(|s| s.trim())
                    .filter_map(|s| match s {
                        "digital_signature" => Some(rcgen::KeyUsagePurpose::DigitalSignature),
                        "content_commitment" => Some(rcgen::KeyUsagePurpose::ContentCommitment),
                        "key_encipherment" => Some(rcgen::KeyUsagePurpose::KeyEncipherment),
                        "data_encipherment" => Some(rcgen::KeyUsagePurpose::DataEncipherment),
                        "key_agreement" => Some(rcgen::KeyUsagePurpose::KeyAgreement),
                        "key_cert_sign" => Some(rcgen::KeyUsagePurpose::KeyCertSign),
                        "crl_sign" => Some(rcgen::KeyUsagePurpose::CrlSign),
                        "encipher_only" => Some(rcgen::KeyUsagePurpose::EncipherOnly),
                        "decipher_only" => Some(rcgen::KeyUsagePurpose::DecipherOnly),
                        _ => None,
                    })
                    .collect();

                let span = call.head;

                let rec = self.gen(params, span)?;
                Ok(PipelineData::Value(rec, pipeline_metadata))
            }
            v => {
                return Err(
                    LabeledError::new(format!("requires list input, got {}", v.get_type()))
                        .with_label("Expected list from pipeline", call.head),
                )
            }
        }
    }
}
