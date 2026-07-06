//! Tests for host/port/service context fidelity types and Lua table construction.

#[cfg(feature = "nse")]
mod tests {
    use eggsec_nse::context::{
        NseContextSource, NseHostContext, NsePortContext, NseServiceContext,
    };
    use eggsec_nse::report::evaluate_rule_with_context;

    #[test]
    fn test_host_context_synthetic() {
        let ctx = NseHostContext::synthetic("192.168.1.1");
        assert_eq!(ctx.ip, "192.168.1.1");
        assert_eq!(ctx.source, NseContextSource::Synthetic);
        assert!(ctx.hostname.is_none());
    }

    #[test]
    fn test_host_context_lua_table() {
        let lua = mlua::Lua::new();
        let ctx = NseHostContext::synthetic("10.0.0.1");
        let table = ctx.to_table(&lua).unwrap();
        assert_eq!(table.get::<String>("ip").unwrap(), "10.0.0.1");
        assert_eq!(
            table.get::<String>("eggsec_context_source").unwrap(),
            "synthetic"
        );
    }

    #[test]
    fn test_port_context_minimal() {
        let ctx = NsePortContext::minimal(80, "tcp");
        assert_eq!(ctx.port, 80);
        assert_eq!(ctx.protocol, "tcp");
        assert_eq!(ctx.state, "unknown");
        assert!(ctx.service.is_none());
        assert_eq!(ctx.source, NseContextSource::Synthetic);
    }

    #[test]
    fn test_port_context_lua_table() {
        let lua = mlua::Lua::new();
        let ctx = NsePortContext::minimal(443, "tcp");
        let table = ctx.to_table(&lua).unwrap();
        assert_eq!(table.get::<u16>("number").unwrap(), 443);
        assert_eq!(table.get::<String>("protocol").unwrap(), "tcp");
        assert_eq!(
            table.get::<String>("eggsec_context_source").unwrap(),
            "synthetic"
        );
    }

    #[test]
    fn test_service_context_lua_table() {
        let lua = mlua::Lua::new();
        let svc = NseServiceContext {
            name: Some("http".to_string()),
            product: Some("Apache".to_string()),
            version: Some("2.4.41".to_string()),
            tunnel: None,
            confidence: Some(0.95),
        };
        let table = svc.to_table(&lua).unwrap();
        assert_eq!(table.get::<String>("name").unwrap(), "http");
        assert_eq!(table.get::<String>("product").unwrap(), "Apache");
        assert_eq!(table.get::<String>("version").unwrap(), "2.4.41");
        assert!((table.get::<f32>("confidence").unwrap() - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_evaluate_rule_with_context_synthetic() {
        let lua = mlua::Lua::new();
        let host = NseHostContext::synthetic("10.0.0.1");
        let port = NsePortContext::minimal(80, "tcp");

        let result = evaluate_rule_with_context(
            "portrule",
            Ok(mlua::Value::Boolean(true)),
            &host,
            Some(&port),
        );

        assert!(result.evaluated);
        assert!(result.matched);
        assert_eq!(result.host_context_source.as_deref(), Some("synthetic"));
        assert_eq!(result.port_context_source.as_deref(), Some("synthetic"));
        // Synthetic context should mark as approximate
        assert_eq!(result.exactness, "approximate");
        assert!(result.fidelity_reason.is_some());
    }

    #[test]
    fn test_context_source_display() {
        assert_eq!(NseContextSource::Scan.to_string(), "scan");
        assert_eq!(NseContextSource::Fixture.to_string(), "fixture");
        assert_eq!(NseContextSource::Synthetic.to_string(), "synthetic");
        assert_eq!(NseContextSource::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_port_context_with_service() {
        let svc = NseServiceContext {
            name: Some("ssh".to_string()),
            product: Some("OpenSSH".to_string()),
            version: Some("8.1p1".to_string()),
            tunnel: None,
            confidence: None,
        };
        let ctx = NsePortContext {
            port: 22,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(svc),
            source: NseContextSource::Scan,
        };

        assert_eq!(ctx.port, 22);
        assert!(ctx.service.is_some());
        assert_eq!(ctx.service.as_ref().unwrap().name.as_deref(), Some("ssh"));

        let lua = mlua::Lua::new();
        let table = ctx.to_table(&lua).unwrap();
        let svc_table: mlua::Table = table.get("service").unwrap();
        assert_eq!(svc_table.get::<String>("name").unwrap(), "ssh");
        assert_eq!(svc_table.get::<String>("product").unwrap(), "OpenSSH");
    }
}
