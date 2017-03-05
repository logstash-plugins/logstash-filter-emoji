# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This plugin maps the severity names or numeric codes as defined in
# https://tools.ietf.org/html/rfc3164#section-4.1.1[RFC 3164] and
# https://tools.ietf.org/html/rfc5424#section-6.2.1[RFC 5424] to the emoji
# as defined in the configuration.

class LogStash::Filters::Emoji < LogStash::Filters::Base

  config_name "emoji"

  # The name of the logstash event field containing the value to be compared for
  # a match by the emoji filter (e.g. `severity`).
  #
  # If this field is an array, only the first value will be used.
  config :field, :validate => :string, :required => true

  # If the target field already exists, this configuration item specifies
  # whether the filter should skip being rewritten as an emoji (default) or
  # overwrite the target field value with the emoji value.
  config :override, :validate => :boolean, :default => false

  # `sev_emergency` selects the emoji/unicode character for Emergency severity
  config :sev_emergency, :validate => :string, :default => "💥"
  # `sev_alert` selects the emoji/unicode character for Alert severity
  config :sev_alert, :validate => :string, :default => "🚨"
  # `sev_critical` selects the emoji/unicode character for Critical severity
  config :sev_critical, :validate => :string, :default => "🔥"
  # `sev_error` selects the emoji/unicode character for Error severity
  config :sev_error, :validate => :string, :default => "❌"
  # `sev_warning` selects the emoji/unicode character for Warning severity
  config :sev_warning, :validate => :string, :default => "⚠️"
  # `sev_notice` selects the emoji/unicode character for Notice severity
  config :sev_notice, :validate => :string, :default => "👀"
  # `sev_info` selects the emoji/unicode character for Informational severity
  config :sev_info, :validate => :string, :default => "ℹ️"
  # `sev_debug` selects the emoji/unicode character for Debug severity
  config :sev_debug, :validate => :string, :default => "🐛"

  # The target field you wish to populate with the emoji. The default
  # is a field named `emoji`. Set this to the same value as the source (`field`)
  # if you want to do a substitution, in this case filter will allways succeed.
  # This will overwrite the old value of the source field!
  config :target, :validate => :string, :default => "emoji"

  # In case no match is found in the event, this will add a default emoji, which
  # will always populate `target`, if the match failed.
  #
  # For example, if we have configured `fallback => "`❓`"`, using this
  # dictionary:
  # [source,ruby]
  #     foo: 👤
  #
  # Then, if logstash received an event with the field `foo` set to 👤, the
  # target field would be set to 👤. However, if logstash received an event with
  # `foo` set to `nope`, then the target field would still be populated, but
  # with the value of ❓.
  # This configuration can be dynamic and include parts of the event using the
  # `%{field}` syntax.
  config :fallback, :validate => :string

  public
  def register
    @dictionary = {
       "^0$|Emergency|EMERGENCY|emerg|EMERG" => @sev_emergency,
       "^1$|Alert|ALERT|alert" => @sev_alert,
       "^2$|Critical|CRITICAL|crit|CRIT" => @sev_critical,
       "^3$|Error|ERROR|err|ERR" => @sev_error,
       "^4$|Warning|WARNING|warn|WARN" => @sev_warning,
       "^5$|Notice|NOTICE|notice" => @sev_notice,
       "^6$|Informational|INFORMATIONAL|info|INFO" => @sev_info,
       "^7$|Debug|DEBUG|debug" => @sev_debug
    }
    @logger.debug? and @logger.debug("#{self.class.name}: Dictionary - ", :dictionary => @dictionary)
    if @exact
      @logger.debug? and @logger.debug("#{self.class.name}: Dictionary matching method - Exact")
    else
      @logger.debug? and @logger.debug("#{self.class.name}: Dictionary matching method - Fuzzy")
    end
  end # def register

  public
  def filter(event)
    return unless event.include?(@field) # Skip if event does not have specified field.
    return if event.include?(@target) and not @override # Skip if @target field already exists and @override is false.

    begin
      #If source field is array use first value and make sure source value is string
      source = event.get(@field).is_a?(Array) ? event.get(@field).first.to_s : event.get(@field).to_s
      matched = false
      key = @dictionary.keys.detect{|k| source.match(Regexp.new(k))}
      if key
        event.set(@target, @dictionary[key] )
        metric.increment(:matches)
        matched = true
      end

      if not matched and @fallback
        event.set(@target, event.sprintf(@fallback))
        metric.increment(:matches)
        matched = true
      end
      filter_matched(event) if matched or @field == @target
    rescue Exception => e
      metric.increment(:failures)
      @logger.error("Something went wrong when attempting to match from dictionary", :exception => e, :field => @field, :event => event)
    end
  end # def filter
end # class LogStash::Filters::Emoji
