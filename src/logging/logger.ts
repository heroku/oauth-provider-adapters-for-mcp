import { redact } from './redaction';

// Ordered from least to most verbose.
export enum LogLevel {
  Silent,
  Fatal,
  Error,
  Warn,
  Info,
  Debug,
  Trace,
}

export enum LogDestination {
  StdOut = 'log',
  StdErr = 'error',
}

export type LogMeta = Record<string, unknown>;

export interface LoggerOptions {
  level?: LogLevel;
  redactPaths?: string[];
  destination?: LogDestination;
}

export interface Logger {
  child(binding: LogMeta): Logger;
  level: LogLevel;
  fatal(msg: string, meta?: LogMeta): void;
  error(msg: string, meta?: LogMeta): void;
  warn(msg: string, meta?: LogMeta): void;
  info(msg: string, meta?: LogMeta): void;
  debug(msg: string, meta?: LogMeta): void;
  trace(msg: string, meta?: LogMeta): void;
}

export class DefaultLogger implements Logger {
  // Defaults for this implementation of Logger
  static readonly defaultLevel = LogLevel.Info;
  static readonly defaultDestination = LogDestination.StdOut;
  static readonly defaultRedactPaths = [];

  private readonly context: LogMeta;
  private readonly writeMessage;

  public readonly destination: LogDestination;
  public redactPaths: string[];
  public level: LogLevel;

  constructor(context: LogMeta, options?: LoggerOptions) {
    this.context = context;
    this.level = options?.level || DefaultLogger.defaultLevel;
    this.destination = options?.destination || DefaultLogger.defaultDestination;
    this.redactPaths = options?.redactPaths || DefaultLogger.defaultRedactPaths;
    this.writeMessage = console[this.destination];
  }

  child(context: LogMeta): Logger {
    const childContext = { ...this.context, ...context };
    const childOptions = {
      level: this.level,
      redactPaths: this.redactPaths,
      destination: this.destination,
    };

    return new DefaultLogger(childContext, childOptions);
  }

  fatal(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Fatal, msg, meta);
  }

  error(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Error, msg, meta);
  }

  warn(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Warn, msg, meta);
  }

  info(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Info, msg, meta);
  }

  debug(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Debug, msg, meta);
  }

  trace(msg: string, meta?: LogMeta): void {
    this.log(LogLevel.Trace, msg, meta);
  }

  private log(level: LogLevel, msg: string, meta?: LogMeta): void {
    if (level === LogLevel.Silent) {
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
