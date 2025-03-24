use nu_plugin::PluginCommand;
use nu_protocol::{record, Category, LabeledError, PipelineData, Signature, Type};
use nu_protocol::{Span, Value};
use oid_registry::OidRegistry;
use x509_parser::prelude::*;

pub struct ParseCommand;

impl ParseCommand {
    fn extensions_to_record(&self, ext: ParsedExtension, span: Span) -> (Value, &'static str) {
        match ext {
            ParsedExtension::BasicConstraints(bc) => (
                Value::record(
                    record!(
                        "ca" => Value::bool(bc.ca, span),
                        "path_len_constraint" => Value::int(bc.path_len_constraint.unwrap_or(0) as i64, span),
                    ),
                    span,
                ),
                "BasicConstraints",
            ),
            ParsedExtension::KeyUsage(ku) => (
                Value::record(
                    record!(
                        "digital_signature" => Value::bool(ku.digital_signature(), span),
                        "non_repudiation" => Value::bool(ku.non_repudiation(), span),
                        "key_encipherment" => Value::bool(ku.key_encipherment(), span),
                        "data_encipherment" => Value::bool(ku.data_encipherment(), span),
                        "key_agreement" => Value::bool(ku.key_agreement(), span),
                        "key_cert_sign" => Value::bool(ku.key_cert_sign(), span),
                        "crl_sign" => Value::bool(ku.crl_sign(), span),
                        "encipher_only" => Value::bool(ku.encipher_only(), span),
                        "decipher_only" => Value::bool(ku.decipher_only(), span),
                    ),
                    span,
                ),
                "KeyUsage",
            ),
            ParsedExtension::ExtendedKeyUsage(eku) => (
                Value::record(
                    record!(
                        "server_auth" => Value::bool(eku.server_auth, span),
                        "client_auth" => Value::bool(eku.client_auth, span),
                        "code_signing" => Value::bool(eku.code_signing, span),
                        "email_protection" => Value::bool(eku.email_protection, span),
                        "time_stamping" => Value::bool(eku.time_stamping, span),
                        "ocscp_signing" => Value::bool(eku.ocsp_signing, span),
                        "any" => Value::bool(eku.any, span),
                        "other" => Value::List {
                            vals: eku
                                .other
                                .iter()
                                .map(|oid| Value::string(oid.to_string(), span))
                                .collect(),
                            internal_span: span,
                        }
                    ),
                    span,
                ),
                "ExtendedKeyUsage",
            ),
            ParsedExtension::SubjectAlternativeName(san) => (
                Value::List {
                    vals: san
                        .general_names
                        .iter()
                        .map(|gn| Value::string(format!("{:?}", gn), span))
                        .collect(),
                    internal_span: span,
                },
                "SubjectAlternativeName",
            ),
            ParsedExtension::AuthorityKeyIdentifier(aki) => (
                Value::record(
                    record!(
                        "key_identifier" => Value::string(
                            aki.key_identifier
                                .as_ref()
                                .map(|ki| format!("{:x}", ki))
                                .unwrap_or_default(),
                            span
                        ),
                        "authority_cert_issuer" => Value::List {
                            vals: aki
                                .authority_cert_issuer
                                .iter()
                                .map(|gn| Value::string(format!("{:?}", gn), span))
                                .collect(),
                            internal_span: span,
                        },
                        "authority_cert_serial" => Value::string(
                            aki.authority_cert_serial
                                .map(|serial| hex::encode(serial.as_ref()))
                                .unwrap_or_default(),
                            span
                        ),
                    ),
                    span,
                ),
                "AuthorityKeyIdentifier",
            ),
            ParsedExtension::SubjectKeyIdentifier(ski) => (
                Value::string(format!("{:x}", ski), span),
                "SubjectKeyIdentifier",
            ),
            _ => (Value::string(format!("{:?}", ext), span), "Other"),
        }
    }

    fn parse(&self, data: &[u8], span: Span) -> Result<Value, LabeledError> {
        let registry = OidRegistry::default().with_crypto();

        let mut ders = Vec::new();
        let pems = Pem::iter_from_buffer(data);
        for pem_result in pems {
            if let Ok(pem) = pem_result {
                if let Ok((_, _cert)) = X509Certificate::from_der(&pem.contents) {
                    ders.push(pem.contents.to_vec());
                }
            }
        }
        if ders.is_empty() {
            ders = vec![data.to_vec()]
        }

        let mut output = Vec::new();
        for der in ders {
            let crt = X509Certificate::from_der(&der)
                .map_err(|e| LabeledError::new(e.to_string()))?
                .1;
            let subject_public_key_value = crt
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .chunks(16)
                .map(|chunk| chunk.join(":"))
                .collect::<Vec<String>>()
                .join("\n");
            let signature_value = crt
                .signature_value
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .chunks(16)
                .map(|chunk| chunk.join(":"))
                .collect::<Vec<String>>()
                .join("\n");
            let rec = record!(
                "version" => Value::int(crt.tbs_certificate.version.0 as i64, span),
                "serial" => Value::string(format!("{:x}", crt.tbs_certificate.serial), span),
                // "signature" => Value::string(crt.tbs_certificate.signature.oid().to_string(), span),
                "issuer" => Value::string(crt.tbs_certificate.issuer.to_string(), span),
                "validity" => Value::record(record!(
                    "not_before" => Value::date(chrono::DateTime::from_timestamp(crt.tbs_certificate.validity.not_before.timestamp(), 0).unwrap_or_default().into(), span),
                    "not_after" => Value::date(chrono::DateTime::from_timestamp(crt.tbs_certificate.validity.not_after.timestamp(), 0).unwrap_or_default().into(), span),
                ), span),
                "subject" => Value::string(crt.tbs_certificate.subject.to_string(), span),
                "subject_pki" => Value::record(record!(
                    "subject_public_key" => Value::string(
                        registry.get(crt.tbs_certificate.subject_pki.algorithm.oid())
                            .map(|oid_entry| oid_entry.sn().to_string())
                            .unwrap_or_else(|| "Unknown".to_string()),
                        span
                    ),
                    "subject_public_key_value" => Value::string(subject_public_key_value, span),
                ), span),
                "extensions" => Value::List {
                    vals: crt
                        .tbs_certificate
                        .extensions()
                        .iter()
                        .map(|ext| {
                            let (value, name) = self.extensions_to_record(
                                ext.parsed_extension().clone(),
                                span
                            );
                            Value::record(record!(
                                "oid" => Value::string(ext.oid.to_id_string(), span),
                                "name" => Value::string(name, span),
                                "critical" => Value::bool(ext.critical, span),
                                "value" => value,
                            ), span)
                        })
                        .collect(),
                    internal_span: span,
                },
                "signature_algorithm" => Value::string(
                    registry.get(crt.signature_algorithm.oid())
                        .map(|oid_entry| oid_entry.sn())
                        .unwrap_or_else(|| "Unknown"),
                    span
                ),
                "signature_value" => Value::string(
                    signature_value,
                    span
                ),
            );
            output.push(Value::record(rec, span));
        }
        Ok(Value::List {
            vals: output,
            internal_span: span,
        })
    }
}

impl nu_plugin::PluginCommand for ParseCommand {
    type Plugin = crate::X509Plugin;

    fn name(&self) -> &str {
        "from x509"
    }

    fn signature(&self) -> nu_protocol::Signature {
        Signature::build(PluginCommand::name(self))
            .allow_variants_without_examples(true)
            .input_output_types(vec![
                (Type::Binary, Type::List(Box::new(Type::Any))),
                (Type::String, Type::List(Box::new(Type::Any))),
            ])
            .category(Category::Experimental)
            .filter()
    }

    fn description(&self) -> &str {
        "Parse x509 certificates"
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        _engine: &nu_plugin::EngineInterface,
        call: &nu_plugin::EvaluatedCall,
        input: nu_protocol::PipelineData,
    ) -> Result<nu_protocol::PipelineData, nu_protocol::LabeledError> {
        match input {
            PipelineData::ByteStream(byte_stream, pipeline_metadata) => {
                let span = byte_stream.span();
                let rec = self.parse(
                    byte_stream
                        .into_bytes()
                        .map_err(|e| LabeledError::new(e.to_string()))?
                        .as_slice(),
                    span,
                )?;
                Ok(PipelineData::Value(rec, pipeline_metadata))
            }
            PipelineData::Value(Value::String { val, internal_span }, pipeline_metadata) => {
                let rec = self.parse(val.as_bytes(), internal_span)?;
                Ok(PipelineData::Value(rec, pipeline_metadata))
            }
            PipelineData::Value(Value::Binary { val, internal_span }, pipeline_metadata) => {
                let rec = self.parse(&val, internal_span)?;
                Ok(PipelineData::Value(rec, pipeline_metadata))
            }
            v => {
                return Err(LabeledError::new(format!(
                    "requires binary|string input, got {}",
                    v.get_type()
                ))
                .with_label("Expected binary|string from pipeline", call.head))
            }
        }
    }
}
