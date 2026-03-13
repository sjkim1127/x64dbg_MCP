use crate::x64dbg::api::log_print;
use tracing::{Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub struct X64DbgLogLayer;

impl<S: Subscriber> Layer<S> for X64DbgLogLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        let mut visitor = StringVisitor::new();
        event.record(&mut visitor);

        let prefix = match level {
            Level::ERROR => "[ERROR] ",
            Level::WARN => "[WARN] ",
            Level::INFO => "[INFO] ",
            Level::DEBUG => "[DEBUG] ",
            Level::TRACE => "[TRACE] ",
        };

        let msg = format!("{}{}\n", prefix, visitor.0);
        log_print(&msg);
    }
}

struct StringVisitor(String);

impl StringVisitor {
    fn new() -> Self {
        Self(String::new())
    }
}

impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}
