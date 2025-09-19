/**
 * Log levels ordered from least to most verbose.
 * Silent disables all logging output.
 */
export enum LogLevel {
  Silent,
  Fatal,
  Error,
  Warn,
  Info,
  Debug,
  Trace,
}

/**
 * Available destinations for log output.
 */
export enum LogDestination {
  StdOut = 'log',
  StdErr = 'error',
}

/**
 * Metadata object that can be attached to log messages.
 */
export type LogMeta = Record<string, unknown>;

/**
 * Configuration options for creating a logger instance.
 */
export interface LoggerOptions {
  /** The minimum log level to output. Defaults to Info. */
  level?: LogLevel;
  /** Array of object paths to redact from log output for security. */
  redactPaths?: string[];
  /** Where to send log output. Defaults to StdOut. */
  destination?: LogDestination;
}

/**
 * Logger interface defining the contract for all logger implementations.
 */
export interface Logger {
  /**
   * Creates a child logger with additional context metadata.
   * @param context - Metadata to bind to all messages from this child logger
   * @returns A new logger instance with the combined context
   */
  child(context: LogMeta): Logger;

  /** The current log level for this logger instance */
  level: LogLevel;

  /**
   * Log a fatal error message. These represent unrecoverable errors.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  fatal(msg: string, meta?: LogMeta): void;

  /**
   * Log an error message. These represent errors that may be recoverable.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  error(msg: string, meta?: LogMeta): void;

  /**
   * Log a warning message. These represent potential issues.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  warn(msg: string, meta?: LogMeta): void;

  /**
   * Log an informational message. These represent normal application flow.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  info(msg: string, meta?: LogMeta): void;

  /**
   * Log a debug message. These are useful for development and troubleshooting.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  debug(msg: string, meta?: LogMeta): void;

  /**
   * Log a trace message. These provide the most detailed information.
   * @param msg - The message to log
   * @param meta - Optional metadata to include with the message
   */
  trace(msg: string, meta?: LogMeta): void;
}

export type LogWriter = (message?: any, ...optionalParams: any[]) => void;
export interface LogTransport {
  log: LogWriter;
  error: LogWriter;
}
