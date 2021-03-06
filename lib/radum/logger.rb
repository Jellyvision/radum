module RADUM
  # Logger constants.
  LOG_NONE = 0
  LOG_NORMAL = 1
  LOG_DEBUG = 2
  
  # The Logger class handles all logging output. Any output RADUM generates
  # aside from exceptions goes through the Logger class. The possible log
  # levels are:
  #
  # * LOG_NONE: Do not output any log information.
  # * LOG_NORMAL: Output normal messages (warnings) for certain situations.
  # * LOG_DEBUG: Output verbose debugging information.
  #
  # The RADUM module automatically instantiates a Logger instance for the
  # module that is accessible through the RADUM::logger method.
  class Logger
    # The default logger level. Logger levels less than or equal to the default
    # logger level will be displayed. Other messages will be ignored. If the
    # logger level is set to LOG_NONE, no log messages will be displayed.
    attr_accessor :default_level
    
    # Create a new Logger instance. A Logger object is automatically created
    # with a default_level of LOG_NORMAL.
    #
    # === Parameter Types
    #
    # * default_level [integer => RADUM log level constant]
    def initialize(default_level)
      @default_level = default_level
      @output = $stdout
    end
    
    # Print a long message with the given log level. If the log level is
    # LOG_NONE, the message will be discarded, otherwise the message will
    # be processed as long as the log level is less than or equal to the
    # default log level. The log level defaults to LOG_NORMAL.
    #
    # === Parameter Types
    #
    # * mesg [String]
    # * log_level [integer => RADUM log level constant]
    def log(mesg, log_level = LOG_NORMAL)
      if @default_level != LOG_NONE && log_level != LOG_NONE &&
         log_level <= @default_level
        @output.puts mesg
      end
    end
    
    # Set the logger output file. The file is opened with mode "a" so it is
    # created if needed and then appended to.
    #
    # === Parameter Types
    #
    # * filename [String]
    def output_file(filename)
      @output = open(filename, "a")
    end
  end
  
  @radum_logger = Logger.new(LOG_NORMAL)
  
  # Access the RADUM Logger instance.
  def RADUM.logger
    @radum_logger
  end
end