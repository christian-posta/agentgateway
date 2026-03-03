use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCoreConfig {
	pub agent_runtime_arn: String,
	pub qualifier: Option<String>,
	pub region: String,
	pub account_id: String,
}

impl AgentCoreConfig {
	pub fn new(arn: String, qualifier: Option<String>) -> anyhow::Result<Self> {
		// arn:aws:bedrock-agentcore:{region}:{accountId}:runtime/{runtimeId}
		let parts: Vec<&str> = arn.splitn(6, ':').collect();
		anyhow::ensure!(parts.len() >= 5, "invalid AgentCore ARN: {}", arn);
		anyhow::ensure!(
			parts.get(2) == Some(&"bedrock-agentcore"),
			"invalid AgentCore ARN (expected service bedrock-agentcore): {}",
			arn
		);
		Ok(Self {
			region: parts[3].to_string(),
			account_id: parts[4].to_string(),
			agent_runtime_arn: arn,
			qualifier,
		})
	}

	pub fn get_host(&self) -> String {
		format!("bedrock-agentcore.{}.amazonaws.com", self.region)
	}

	pub fn get_path(&self) -> String {
		let encoded = utf8_percent_encode(&self.agent_runtime_arn, NON_ALPHANUMERIC);
		// API accepts either agentRuntimeArn alone (in path) OR agentId+accountId; not both.
		// Since we put the full ARN in the path, do not add accountId query param.
		match &self.qualifier {
			Some(q) => format!("/runtimes/{encoded}/invocations?qualifier={q}"),
			None => format!("/runtimes/{encoded}/invocations"),
		}
	}
}
