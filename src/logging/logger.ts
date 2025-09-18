import { redact } from './redaction.js';

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

export class DefaultLogger implements Logger {
  // Defaults for this implementation of Logger
  static readonly defaultLevel = LogLevel.Info;
  static readonly defaultDestination = LogDestination.StdOut;
  static readonly defaultRedactPaths = [];

  private readonly context: LogMeta;
  private readonly writeMessage;
  private readonly transport: any;

  public readonly destination: LogDestination;
  public redactPaths: string[];
  public level: LogLevel;

  constructor(
    context: LogMeta,
    options?: LoggerOptions,
    transport: any = console
  ) {
    this.context = context;
    this.level = options?.level ?? DefaultLogger.defaultLevel;
    this.destination = options?.destination ?? DefaultLogger.defaultDestination;
    this.redactPaths = options?.redactPaths ?? DefaultLogger.defaultRedactPaths;
    this.transport = transport;
    this.writeMessage = transport[this.destination].bind(transport);
  }

  public child(context: LogMeta): Logger {
    const childContext = { ...this.context, ...context };
    const childOptions = {
      level: this.level,
      redactPaths: this.redactPaths,
      destination: this.destination,
    };

    return new DefaultLogger(childContext, childOptions, this.transport);
  }

  public fatal(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Fatal, msg, meta);
  }

  public error(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Error, msg, meta);
  }

  public warn(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Warn, msg, meta);
  }

  public info(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Info, msg, meta);
  }

  public debug(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Debug, msg, meta);
  }

  public trace(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Trace, msg, meta);
  }

  private log(level: LogLevel, msg: string, meta?: LogMeta): void {
    if (this.level === LogLevel.Silent) {
      return;
    }

    if (level <= this.level) {
      const message = {
        message: msg,
        level: LogLevel[level],
        ...redact(this.context, this.redactPaths),
        ...redact(meta, this.redactPaths),
      };

      this.writeMessage(message);
    }
  }
}
