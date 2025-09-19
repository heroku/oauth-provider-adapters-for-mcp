import { redact } from './redaction.js';
import {
  Logger,
  LogLevel,
  LogDestination,
  LogMeta,
  LoggerOptions,
  LogTransport,
} from './types.js';

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
    transport: LogTransport = console
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
