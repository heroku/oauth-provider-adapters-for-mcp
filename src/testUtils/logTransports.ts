import { LogTransport } from '../logging/types.js';

// Emulates console transport
export class MockTransport implements LogTransport {
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
