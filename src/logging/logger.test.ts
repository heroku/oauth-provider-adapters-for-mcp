import { expect } from 'chai';
import { DefaultLogger, LogLevel, LogDestination } from './logger.js';

class MockTransport {
  public logs: any[];
  public errors: any[];

  constructor() {
    this.logs = [];
    this.errors = [];
  }

  log(message: any) {
    this.logs.push(message);
  }

  error(message: any) {
    this.errors.push(message);
  }
}

describe('LogLevel', () => {
  it('defines logLevels in order of least verbose to most verbose', () => {
    expect(LogLevel.Silent).to.equal(0);
    expect(LogLevel.Fatal).to.equal(1);
    expect(LogLevel.Error).to.equal(2);
    expect(LogLevel.Warn).to.equal(3);
    expect(LogLevel.Info).to.equal(4);
    expect(LogLevel.Debug).to.equal(5);
    expect(LogLevel.Trace).to.equal(6);
  });
});

describe('DefaultLogger', () => {
  it('has a default log-level of Info', () => {
    const logger = new DefaultLogger({});
    expect(logger.level).to.equal(LogLevel.Info);
  });

  it('has a default destination of StdOut', () => {
    const logger = new DefaultLogger({});
    expect(logger.destination).to.equal(LogDestination.StdOut);
  });

  it('has a default redactPaths array that is empty', () => {
    const logger = new DefaultLogger({});
    expect(logger.redactPaths).to.deep.equal([]);
  });

  describe('with mock transport', () => {
    let mockTransport: MockTransport;

    beforeEach(() => {
      mockTransport = new MockTransport();
    });

    it('always logs its context in addition to the log msg and meta', () => {
      const logger = new DefaultLogger(
        { service: 'test-service', version: '1.0.0' },
        { level: LogLevel.Info },
        mockTransport
      );

      logger.info('Test message', { requestId: '123' });

      expect(mockTransport.logs).to.have.length(1);
      const loggedMessage = mockTransport.logs[0];
      expect(loggedMessage).to.deep.equal({
        message: 'Test message',
        level: 'Info',
        service: 'test-service',
        version: '1.0.0',
        requestId: '123',
      });
    });

    it('applies redaction to log meta', () => {
      const logger = new DefaultLogger(
        { service: 'test-service' },
        { level: LogLevel.Info, redactPaths: ['password', 'token'] },
        mockTransport
      );

      logger.info('Login attempt', {
        username: 'user',
        password: 'secret123',
        token: 'abc456',
      });

      expect(mockTransport.logs).to.have.length(1);
      const loggedMessage = mockTransport.logs[0];
      expect(loggedMessage).to.deep.equal({
        message: 'Login attempt',
        level: 'Info',
        service: 'test-service',
        username: 'user',
        password: '[redacted]',
        token: '[redacted]',
      });
    });

    it('applies redaction to log context', () => {
      const logger = new DefaultLogger(
        {
          service: 'test-service',
          apiKey: 'secret-key-123',
          userId: 'user-456',
        },
        { level: LogLevel.Info, redactPaths: ['apiKey'] },
        mockTransport
      );

      logger.info('Processing request', { action: 'create' });

      expect(mockTransport.logs).to.have.length(1);
      const loggedMessage = mockTransport.logs[0];
      expect(loggedMessage).to.deep.equal({
        message: 'Processing request',
        level: 'Info',
        service: 'test-service',
        apiKey: '[redacted]',
        userId: 'user-456',
        action: 'create',
      });
    });

    it('logs nothing when log-level is silent', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Silent },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.info('Info message');

      expect(mockTransport.logs).to.have.length(0);
    });

    it('logs fatal messages when log-level is fatal or greater', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Fatal },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.info('Info message');

      expect(mockTransport.logs).to.have.length(1);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[0].message).to.equal('Fatal error');
    });

    it('logs error messages when log-level is error or greater', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Error },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.warn('Warn message');
      logger.info('Info message');

      expect(mockTransport.logs).to.have.length(2);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[1].level).to.equal('Error');
    });

    it('logs warn messages when log-level is warn or greater', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Warn },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.warn('Warn message');
      logger.info('Info message');
      logger.debug('Debug message');

      expect(mockTransport.logs).to.have.length(3);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[1].level).to.equal('Error');
      expect(mockTransport.logs[2].level).to.equal('Warn');
    });

    it('logs info messages when log-level is info or greater', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Info },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.warn('Warn message');
      logger.info('Info message');
      logger.debug('Debug message');
      logger.trace('Trace message');

      expect(mockTransport.logs).to.have.length(4);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[1].level).to.equal('Error');
      expect(mockTransport.logs[2].level).to.equal('Warn');
      expect(mockTransport.logs[3].level).to.equal('Info');
    });

    it('logs debug messages when log-level is debug or greater', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Debug },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.warn('Warn message');
      logger.info('Info message');
      logger.debug('Debug message');
      logger.trace('Trace message');

      expect(mockTransport.logs).to.have.length(5);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[1].level).to.equal('Error');
      expect(mockTransport.logs[2].level).to.equal('Warn');
      expect(mockTransport.logs[3].level).to.equal('Info');
      expect(mockTransport.logs[4].level).to.equal('Debug');
    });

    it('logs trace messages when log-level is trace', () => {
      const logger = new DefaultLogger(
        {},
        { level: LogLevel.Trace },
        mockTransport
      );

      logger.fatal('Fatal error');
      logger.error('Error message');
      logger.warn('Warn message');
      logger.info('Info message');
      logger.debug('Debug message');
      logger.trace('Trace message');

      expect(mockTransport.logs).to.have.length(6);
      expect(mockTransport.logs[0].level).to.equal('Fatal');
      expect(mockTransport.logs[1].level).to.equal('Error');
      expect(mockTransport.logs[2].level).to.equal('Warn');
      expect(mockTransport.logs[3].level).to.equal('Info');
      expect(mockTransport.logs[4].level).to.equal('Debug');
      expect(mockTransport.logs[5].level).to.equal('Trace');
    });

    it("carries its parent's logger settings and context forward when a child logger is created", () => {
      const parentLogger = new DefaultLogger(
        { service: 'parent-service', version: '1.0.0' },
        {
          level: LogLevel.Debug,
          redactPaths: ['secret'],
          destination: LogDestination.StdErr,
        },
        mockTransport
      );

      const childLogger = parentLogger.child({
        module: 'auth',
        secret: 'hidden-value',
      });

      childLogger.debug('Child message', { action: 'login' });

      expect(mockTransport.errors).to.have.length(1);
      const loggedMessage = mockTransport.errors[0];
      expect(loggedMessage).to.deep.equal({
        message: 'Child message',
        level: 'Debug',
        service: 'parent-service',
        version: '1.0.0',
        module: 'auth',
        secret: '[redacted]',
        action: 'login',
      });

      expect(childLogger.level).to.equal(LogLevel.Debug);
      expect((childLogger as DefaultLogger).destination).to.equal(
        LogDestination.StdErr
      );
      expect((childLogger as DefaultLogger).redactPaths).to.deep.equal([
        'secret',
      ]);
    });
  });
});
