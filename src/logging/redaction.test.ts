import { expect } from 'chai';
import { redact } from './redaction.js';

describe('redact', () => {
  it('redacts values for simple objects', () => {
    const obj = {
      name: 'bob',
      email: 'bob@example.com',
      password: 'password123',
    };

    const paths = ['email', 'password'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      email: '[redacted]',
      password: '[redacted]',
    });
  });

  it('redacts nested values from objects', () => {
    const obj = {
      name: 'bob',
      address: {
        street: '123 Cedar Ln',
        city: 'Denver',
        state: 'CO',
      },
      email: 'bob@example.com',
    };

    const paths = ['email', 'address.street'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      address: {
        street: '[redacted]',
        city: 'Denver',
        state: 'CO',
      },
      email: '[redacted]',
    });
  });

  it('redacts nested values from arrays', () => {
    const obj = {
      name: 'bob',
      creds: ['captainbob', 'password123'],
    };

    const paths = ['creds.1'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      creds: ['captainbob', '[redacted]'],
    });
  });

  it('redacts all target values in a nested array of objects', () => {
    const obj = {
      name: 'bob',
      identities: [
        { site: 'https://reddit.com', creds: ['captainbob', 'password123'] },
        { site: 'https://oldcars.com', creds: ['captainbob68', 'password456'] },
      ],
    };

    const paths = ['identities.creds.1'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      identities: [
        { site: 'https://reddit.com', creds: ['captainbob', '[redacted]'] },
        { site: 'https://oldcars.com', creds: ['captainbob68', '[redacted]'] },
      ],
    });
  });

  it('redacts specific target values in a nested array of objects', () => {
    const obj = {
      name: 'bob',
      identities: [
        { site: 'https://reddit.com', creds: ['captainbob', 'password123'] },
        { site: 'https://oldcars.com', creds: ['captainbob68', 'password456'] },
      ],
    };

    const paths = ['identities.0.creds.1'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      identities: [
        { site: 'https://reddit.com', creds: ['captainbob', '[redacted]'] },
        { site: 'https://oldcars.com', creds: ['captainbob68', 'password456'] },
      ],
    });
  });

  it("does not redact values who's key shares the same name with another value somewhere else in the structure", () => {
    const obj = {
      name: 'bob',
      addresses: [
        {
          name: 'home',
          street: '123 Cedar Ln',
          city: 'Denver',
          state: 'CO',
        },
        {
          name: 'work',
          street: '4829 W. Cables Ave.',
          city: 'Westminster',
          state: 'CO',
        },
      ],
      email: 'bob@example.com',
    };

    const paths = ['email', 'addresses.name', 'addresses.street'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      addresses: [
        {
          name: '[redacted]',
          street: '[redacted]',
          city: 'Denver',
          state: 'CO',
        },
        {
          name: '[redacted]',
          street: '[redacted]',
          city: 'Westminster',
          state: 'CO',
        },
      ],
      email: '[redacted]',
    });
  });

  it('handles null and undefined input objects', () => {
    expect(redact(null, ['path'])).to.be.null;
    expect(redact(undefined, ['path'])).to.be.undefined;
  });

  it('handles primitive input values', () => {
    expect(redact('string', ['path'])).to.equal('string');
    expect(redact(123, ['path'])).to.equal(123);
    expect(redact(true, ['path'])).to.be.true;
  });

  it('returns original object when paths array is empty', () => {
    const obj = { name: 'bob', password: 'secret' };
    const result = redact(obj, []);

    expect(result).to.eql(obj);
  });

  it('ignores nonexistent paths', () => {
    const obj = { name: 'bob', email: 'bob@example.com' };
    const paths = ['nonexistent', 'also.nonexistent', 'email'];
    const result = redact(obj, paths);

    expect(result).to.eql({
      name: 'bob',
      email: '[redacted]',
    });
  });

  it('handles empty objects and arrays', () => {
    expect(redact({}, ['nonexistent'])).to.eql({});
    expect(redact([], ['0'])).to.eql([]);
  });

  it('uses custom redaction values', () => {
    const obj = { password: 'secret', token: 'abc123' };
    const result = redact(obj, ['password', 'token'], '***HIDDEN***');

    expect(result).to.eql({
      password: '***HIDDEN***',
      token: '***HIDDEN***',
    });
  });

  it('handles empty string as redaction value', () => {
    const obj = { password: 'secret' };
    const result = redact(obj, ['password'], '');

    expect(result).to.eql({
      password: '',
    });
  });
});
