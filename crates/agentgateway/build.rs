// This build script is used to generate the rust source files that
// we need for XDS GRPC communication.
fn main() -> Result<(), anyhow::Error> {
	// When building with the ui feature, ensure ui/out exists so include_dir! in ui.rs can embed it.
	// If the UI hasn't been built (e.g. local `cargo build --features ui` without Docker),
	// create a minimal placeholder so the crate compiles.
	if std::env::var("CARGO_FEATURE_UI").is_ok() {
		let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
		let ui_out = std::path::Path::new(&manifest_dir).join("../../ui/out");
		if !ui_out.is_dir() {
			std::fs::create_dir_all(&ui_out)?;
			// Minimal placeholder so /ui serves something
			let index = ui_out.join("index.html");
			if !index.exists() {
				std::fs::write(
					index,
					"<!DOCTYPE html><html><head><title>Agent Gateway</title></head><body><p>UI assets not built. Run <code>cd ui && npm install && npm run build</code> and rebuild.</p></body></html>",
				)?;
			}
			println!("cargo:warning=ui/out was missing; created placeholder. Build the UI with 'cd ui && npm run build' for the full interface.");
		}
	}

	let proto_files = [
		"proto/ext_proc.proto",
		"proto/ext_authz.proto",
		"proto/rls.proto",
		"proto/resource.proto",
		"proto/workload.proto",
		"proto/citadel.proto",
	]
	.iter()
	.map(|name| std::env::current_dir().unwrap().join(name))
	.collect::<Vec<_>>();
	let include_dirs = ["proto/"]
		.iter()
		.map(|i| std::env::current_dir().unwrap().join(i))
		.collect::<Vec<_>>();
	let config = {
		let mut c = prost_build::Config::new();
		c.disable_comments(Some("."));
		c.bytes([
			".istio.workload.Workload",
			".istio.workload.Service",
			".istio.workload.GatewayAddress",
			".istio.workload.Address",
		]);
		c.extern_path(".google.protobuf.Value", "::prost_wkt_types::Value");
		c.extern_path(".google.protobuf.Struct", "::prost_wkt_types::Struct");
		c
	};
	let fds = protox::compile(&proto_files, &include_dirs)?;
	tonic_prost_build::configure()
		.build_server(true)
		.compile_fds_with_config(fds, config)?;

	// This tells cargo to re-run this build script only when the proto files
	// we're interested in change or the any of the proto directories were updated.
	for path in [proto_files, include_dirs].concat() {
		println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
	}
	Ok(())
}
