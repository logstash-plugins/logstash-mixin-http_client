# 2.2.2
  - New dependency requirements for logstash-core for the 5.0 release
# 2.2.1
 * Use a superior 'validate_after_inactivity' default of 200ms to force more frequent checks for broken keepalive situations
# 2.2.0
 * Bump manticore version to be at least 0.5.2 for #close support
# 2.1.0
 * Default `automatic_retries` to 1 to fix connections to hosts with broken keepalive
 * Add `non_idempotent_retries` option
# 2.0.0
 * Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 * Dependency on logstash-core update to 2.0
# 1.0.2
  * Add 'verify_cert' config option
# 1.0.1
  * Default to 0 automatic_retries
# 1.0.0
  * Allow to use either V1 or V2 of the `AWS-SDK` in your plugins. Fixes: https://github.com/logstash-plugins/logstash-mixin-aws/issues/8
