'use strict';
const __compactRuntime = require('@midnight-ntwrk/compact-runtime');
const expectedRuntimeVersionString = '0.8.1';
const expectedRuntimeVersion = expectedRuntimeVersionString.split('-')[0].split('.').map(Number);
const actualRuntimeVersion = __compactRuntime.versionString.split('-')[0].split('.').map(Number);
if (expectedRuntimeVersion[0] != actualRuntimeVersion[0]
     || (actualRuntimeVersion[0] == 0 && expectedRuntimeVersion[1] != actualRuntimeVersion[1])
     || expectedRuntimeVersion[1] > actualRuntimeVersion[1]
     || (expectedRuntimeVersion[1] == actualRuntimeVersion[1] && expectedRuntimeVersion[2] > actualRuntimeVersion[2]))
   throw new __compactRuntime.CompactError(`Version mismatch: compiled code expects ${expectedRuntimeVersionString}, runtime is ${__compactRuntime.versionString}`);
{ const MAX_FIELD = 52435875175126190479447740508185965837690552500527637822603658699938581184512n;
  if (__compactRuntime.MAX_FIELD !== MAX_FIELD)
     throw new __compactRuntime.CompactError(`compiler thinks maximum field value is ${MAX_FIELD}; run time thinks it is ${__compactRuntime.MAX_FIELD}`)
}

var PaymentStatus;
(function (PaymentStatus) {
  PaymentStatus[PaymentStatus['PENDING'] = 0] = 'PENDING';
  PaymentStatus[PaymentStatus['COMPLETED'] = 1] = 'COMPLETED';
  PaymentStatus[PaymentStatus['EXPORTED'] = 2] = 'EXPORTED';
})(PaymentStatus = exports.PaymentStatus || (exports.PaymentStatus = {}));

const _descriptor_0 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_1 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

const _descriptor_2 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

const _descriptor_3 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

class _PaymentReceipt_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_3.alignment().concat(_descriptor_0.alignment().concat(_descriptor_2.alignment().concat(_descriptor_0.alignment()))));
  }
  fromValue(value_0) {
    return {
      nullifier: _descriptor_0.fromValue(value_0),
      pricingTier: _descriptor_3.fromValue(value_0),
      region: _descriptor_0.fromValue(value_0),
      timestamp: _descriptor_2.fromValue(value_0),
      providerCommitment: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.nullifier).concat(_descriptor_3.toValue(value_0.pricingTier).concat(_descriptor_0.toValue(value_0.region).concat(_descriptor_2.toValue(value_0.timestamp).concat(_descriptor_0.toValue(value_0.providerCommitment)))));
  }
}

const _descriptor_4 = new _PaymentReceipt_0();

const _descriptor_5 = new __compactRuntime.CompactTypeVector(2, _descriptor_0);

const _descriptor_6 = new __compactRuntime.CompactTypeVector(4, _descriptor_0);

const _descriptor_7 = new __compactRuntime.CompactTypeBoolean();

class _ContractAddress_0 {
  alignment() {
    return _descriptor_0.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bytes);
  }
}

const _descriptor_8 = new _ContractAddress_0();

const _descriptor_9 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

class Contract {
  witnesses;
  constructor(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract constructor: expected 1 argument, received ${args_0.length}`);
    }
    const witnesses_0 = args_0[0];
    if (typeof(witnesses_0) !== 'object') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor is not an object');
    }
    if (typeof(witnesses_0.userSecretKey) !== 'function') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor does not contain a function-valued field named userSecretKey');
    }
    this.witnesses = witnesses_0;
    this.circuits = {
      generateNullifier(context, ...args_1) {
        return { result: pureCircuits.generateNullifier(...args_1), context };
      },
      commitmentHash(context, ...args_1) {
        return { result: pureCircuits.commitmentHash(...args_1), context };
      },
      payForVPN: (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`payForVPN: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const pricingTier_0 = args_1[1];
        const region_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.originalState != undefined && contextOrig_0.transactionContext != undefined)) {
          __compactRuntime.type_error('payForVPN',
                                      'argument 1 (as invoked from Typescript)',
                                      'vpn-payment.compact line 111 char 1',
                                      'CircuitContext',
                                      contextOrig_0)
        }
        if (!(typeof(pricingTier_0) === 'bigint' && pricingTier_0 >= 0n && pricingTier_0 <= 255n)) {
          __compactRuntime.type_error('payForVPN',
                                      'argument 1 (argument 2 as invoked from Typescript)',
                                      'vpn-payment.compact line 111 char 1',
                                      'Uint<0..255>',
                                      pricingTier_0)
        }
        if (!(region_0.buffer instanceof ArrayBuffer && region_0.BYTES_PER_ELEMENT === 1 && region_0.length === 32)) {
          __compactRuntime.type_error('payForVPN',
                                      'argument 2 (argument 3 as invoked from Typescript)',
                                      'vpn-payment.compact line 111 char 1',
                                      'Bytes<32>',
                                      region_0)
        }
        const context = { ...contextOrig_0 };
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(pricingTier_0).concat(_descriptor_0.toValue(region_0)),
            alignment: _descriptor_3.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._payForVPN_0(context,
                                           partialProofData,
                                           pricingTier_0,
                                           region_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        return { result: result_0, context: context, proofData: partialProofData };
      },
      verifyPaymentExists: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`verifyPaymentExists: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const expectedNullifier_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.originalState != undefined && contextOrig_0.transactionContext != undefined)) {
          __compactRuntime.type_error('verifyPaymentExists',
                                      'argument 1 (as invoked from Typescript)',
                                      'vpn-payment.compact line 150 char 1',
                                      'CircuitContext',
                                      contextOrig_0)
        }
        if (!(expectedNullifier_0.buffer instanceof ArrayBuffer && expectedNullifier_0.BYTES_PER_ELEMENT === 1 && expectedNullifier_0.length === 32)) {
          __compactRuntime.type_error('verifyPaymentExists',
                                      'argument 1 (argument 2 as invoked from Typescript)',
                                      'vpn-payment.compact line 150 char 1',
                                      'Bytes<32>',
                                      expectedNullifier_0)
        }
        const context = { ...contextOrig_0 };
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(expectedNullifier_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._verifyPaymentExists_0(context,
                                                     partialProofData,
                                                     expectedNullifier_0);
        partialProofData.output = { value: _descriptor_2.toValue(result_0), alignment: _descriptor_2.alignment() };
        return { result: result_0, context: context, proofData: partialProofData };
      },
      updateProvider: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`updateProvider: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const newProviderCommitment_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.originalState != undefined && contextOrig_0.transactionContext != undefined)) {
          __compactRuntime.type_error('updateProvider',
                                      'argument 1 (as invoked from Typescript)',
                                      'vpn-payment.compact line 159 char 1',
                                      'CircuitContext',
                                      contextOrig_0)
        }
        if (!(newProviderCommitment_0.buffer instanceof ArrayBuffer && newProviderCommitment_0.BYTES_PER_ELEMENT === 1 && newProviderCommitment_0.length === 32)) {
          __compactRuntime.type_error('updateProvider',
                                      'argument 1 (argument 2 as invoked from Typescript)',
                                      'vpn-payment.compact line 159 char 1',
                                      'Bytes<32>',
                                      newProviderCommitment_0)
        }
        const context = { ...contextOrig_0 };
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(newProviderCommitment_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._updateProvider_0(context,
                                                partialProofData,
                                                newProviderCommitment_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData };
      }
    };
    this.impureCircuits = {
      payForVPN: this.circuits.payForVPN,
      verifyPaymentExists: this.circuits.verifyPaymentExists,
      updateProvider: this.circuits.updateProvider
    };
  }
  initialState(...args_0) {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const constructorContext_0 = args_0[0];
    const providerAddr_0 = args_0[1];
    if (typeof(constructorContext_0) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'constructorContext' in argument 1 (as invoked from Typescript) to be an object`);
    }
    if (!('initialPrivateState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialPrivateState' in argument 1 (as invoked from Typescript)`);
    }
    if (!('initialZswapLocalState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript)`);
    }
    if (typeof(constructorContext_0.initialZswapLocalState) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript) to be an object`);
    }
    if (!(providerAddr_0.buffer instanceof ArrayBuffer && providerAddr_0.BYTES_PER_ELEMENT === 1 && providerAddr_0.length === 32)) {
      __compactRuntime.type_error('Contract state constructor',
                                  'argument 1 (argument 2 as invoked from Typescript)',
                                  'vpn-payment.compact line 65 char 1',
                                  'Bytes<32>',
                                  providerAddr_0)
    }
    const state_0 = new __compactRuntime.ContractState();
    let stateValue_0 = __compactRuntime.StateValue.newArray();
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    state_0.data = stateValue_0;
    state_0.setOperation('payForVPN', new __compactRuntime.ContractOperation());
    state_0.setOperation('verifyPaymentExists', new __compactRuntime.ContractOperation());
    state_0.setOperation('updateProvider', new __compactRuntime.ContractOperation());
    const context = {
      originalState: state_0,
      currentPrivateState: constructorContext_0.initialPrivateState,
      currentZswapLocalState: constructorContext_0.initialZswapLocalState,
      transactionContext: new __compactRuntime.QueryContext(state_0.data, __compactRuntime.dummyContractAddress())
    };
    const partialProofData = {
      input: { value: [], alignment: [] },
      output: undefined,
      publicTranscript: [],
      privateTranscriptOutputs: []
    };
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(new Uint8Array(32)),
                                                                            alignment: _descriptor_0.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(1n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                            alignment: _descriptor_2.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(2n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                            alignment: _descriptor_2.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(3n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                            alignment: _descriptor_2.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(4n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                            alignment: _descriptor_2.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(providerAddr_0),
                                                                            alignment: _descriptor_0.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    const tmp_0 = 3n;
    Contract._query(context,
                    partialProofData,
                    [
                     { idx: { cached: false,
                              pushPath: true,
                              path: [
                                     { tag: 'value',
                                       value: { value: _descriptor_3.toValue(1n),
                                                alignment: _descriptor_3.alignment() } }] } },
                     { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                            { value: _descriptor_1.toValue(tmp_0),
                                              alignment: _descriptor_1.alignment() }
                                              .value
                                          )) } },
                     { ins: { cached: true, n: 1 } }]);
    const tmp_1 = 1n;
    Contract._query(context,
                    partialProofData,
                    [
                     { idx: { cached: false,
                              pushPath: true,
                              path: [
                                     { tag: 'value',
                                       value: { value: _descriptor_3.toValue(4n),
                                                alignment: _descriptor_3.alignment() } }] } },
                     { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                            { value: _descriptor_1.toValue(tmp_1),
                                              alignment: _descriptor_1.alignment() }
                                              .value
                                          )) } },
                     { ins: { cached: true, n: 1 } }]);
    state_0.data = context.transactionContext.state;
    return {
      currentContractState: state_0,
      currentPrivateState: context.currentPrivateState,
      currentZswapLocalState: context.currentZswapLocalState
    }
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_6, value_0);
    return result_0;
  }
  _persistentHash_1(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_5, value_0);
    return result_0;
  }
  _userSecretKey_0(context, partialProofData) {
    const witnessContext_0 = __compactRuntime.witnessContext(ledger(context.transactionContext.state), context.currentPrivateState, context.transactionContext.address);
    const [nextPrivateState_0, result_0] = this.witnesses.userSecretKey(witnessContext_0);
    context.currentPrivateState = nextPrivateState_0;
    if (!(result_0.buffer instanceof ArrayBuffer && result_0.BYTES_PER_ELEMENT === 1 && result_0.length === 32)) {
      __compactRuntime.type_error('userSecretKey',
                                  'return value',
                                  'vpn-payment.compact line 76 char 1',
                                  'Bytes<32>',
                                  result_0)
    }
    partialProofData.privateTranscriptOutputs.push({
      value: _descriptor_0.toValue(result_0),
      alignment: _descriptor_0.alignment()
    });
    return result_0;
  }
  _generateNullifier_0(secretKey_0, seq_0, tierIndex_0) {
    return this._persistentHash_0([new Uint8Array([118, 112, 110, 58, 110, 117, 108, 108, 105, 102, 105, 101, 114, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                   secretKey_0,
                                   seq_0,
                                   tierIndex_0]);
  }
  _commitmentHash_0(data_0, salt_0) {
    return this._persistentHash_1([data_0, salt_0]);
  }
  _payForVPN_0(context, partialProofData, pricingTier_0, region_0) {
    __compactRuntime.assert(this._equal_0(pricingTier_0, 0n)
                            ||
                            this._equal_1(pricingTier_0, 1n)
                            ||
                            this._equal_2(pricingTier_0, 2n),
                            'Invalid pricing tier');
    const secretKey_0 = this._userSecretKey_0(context, partialProofData);
    const seqBytes_0 = __compactRuntime.convert_bigint_to_Uint8Array(32,
                                                                     _descriptor_2.fromValue(Contract._query(context,
                                                                                                             partialProofData,
                                                                                                             [
                                                                                                              { dup: { n: 0 } },
                                                                                                              { idx: { cached: false,
                                                                                                                       pushPath: false,
                                                                                                                       path: [
                                                                                                                              { tag: 'value',
                                                                                                                                value: { value: _descriptor_3.toValue(4n),
                                                                                                                                         alignment: _descriptor_3.alignment() } }] } },
                                                                                                              { popeq: { cached: true,
                                                                                                                         result: undefined } }]).value));
    const tierBytes_0 = __compactRuntime.convert_bigint_to_Uint8Array(32,
                                                                      pricingTier_0);
    const nullifier_0 = this._generateNullifier_0(secretKey_0,
                                                  seqBytes_0,
                                                  tierBytes_0);
    const receipt_0 = { nullifier: nullifier_0,
                        pricingTier: pricingTier_0,
                        region: region_0,
                        timestamp:
                          ((t1) => {
                            if (t1 > 18446744073709551615n) {
                              throw new __compactRuntime.CompactError('vpn-payment.compact line 136 char 25: cast from field value to Uint value failed: ' + t1 + ' is greater than 18446744073709551615');
                            }
                            return t1;
                          })(_descriptor_2.fromValue(Contract._query(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_3.toValue(4n),
                                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value)),
                        providerCommitment:
                          _descriptor_0.fromValue(Contract._query(context,
                                                                  partialProofData,
                                                                  [
                                                                   { dup: { n: 0 } },
                                                                   { idx: { cached: false,
                                                                            pushPath: false,
                                                                            path: [
                                                                                   { tag: 'value',
                                                                                     value: { value: _descriptor_3.toValue(0n),
                                                                                              alignment: _descriptor_3.alignment() } }] } },
                                                                   { popeq: { cached: false,
                                                                              result: undefined } }]).value) };
    const tmp_0 = 1n;
    Contract._query(context,
                    partialProofData,
                    [
                     { idx: { cached: false,
                              pushPath: true,
                              path: [
                                     { tag: 'value',
                                       value: { value: _descriptor_3.toValue(2n),
                                                alignment: _descriptor_3.alignment() } }] } },
                     { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                            { value: _descriptor_1.toValue(tmp_0),
                                              alignment: _descriptor_1.alignment() }
                                              .value
                                          )) } },
                     { ins: { cached: true, n: 1 } }]);
    const tmp_1 = 1n;
    Contract._query(context,
                    partialProofData,
                    [
                     { idx: { cached: false,
                              pushPath: true,
                              path: [
                                     { tag: 'value',
                                       value: { value: _descriptor_3.toValue(4n),
                                                alignment: _descriptor_3.alignment() } }] } },
                     { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                            { value: _descriptor_1.toValue(tmp_1),
                                              alignment: _descriptor_1.alignment() }
                                              .value
                                          )) } },
                     { ins: { cached: true, n: 1 } }]);
    const tmp_2 = 1n;
    Contract._query(context,
                    partialProofData,
                    [
                     { idx: { cached: false,
                              pushPath: true,
                              path: [
                                     { tag: 'value',
                                       value: { value: _descriptor_3.toValue(3n),
                                                alignment: _descriptor_3.alignment() } }] } },
                     { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                            { value: _descriptor_1.toValue(tmp_2),
                                              alignment: _descriptor_1.alignment() }
                                              .value
                                          )) } },
                     { ins: { cached: true, n: 1 } }]);
    return receipt_0;
  }
  _verifyPaymentExists_0(context, partialProofData, expectedNullifier_0) {
    return ((t1) => {
             if (t1 > 18446744073709551615n) {
               throw new __compactRuntime.CompactError('vpn-payment.compact line 155 char 10: cast from field value to Uint value failed: ' + t1 + ' is greater than 18446744073709551615');
             }
             return t1;
           })(_descriptor_2.fromValue(Contract._query(context,
                                                      partialProofData,
                                                      [
                                                       { dup: { n: 0 } },
                                                       { idx: { cached: false,
                                                                pushPath: false,
                                                                path: [
                                                                       { tag: 'value',
                                                                         value: { value: _descriptor_3.toValue(3n),
                                                                                  alignment: _descriptor_3.alignment() } }] } },
                                                       { popeq: { cached: true,
                                                                  result: undefined } }]).value));
  }
  _updateProvider_0(context, partialProofData, newProviderCommitment_0) {
    Contract._query(context,
                    partialProofData,
                    [
                     { push: { storage: false,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                            alignment: _descriptor_3.alignment() }).encode() } },
                     { push: { storage: true,
                               value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(newProviderCommitment_0),
                                                                            alignment: _descriptor_0.alignment() }).encode() } },
                     { ins: { cached: false, n: 1 } }]);
    return [];
  }
  _equal_0(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_1(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_2(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  static _query(context, partialProofData, prog) {
    var res;
    try {
      res = context.transactionContext.query(prog, __compactRuntime.CostModel.dummyCostModel());
    } catch (err) {
      throw new __compactRuntime.CompactError(err.toString());
    }
    context.transactionContext = res.context;
    var reads = res.events.filter((e) => e.tag === 'read');
    var i = 0;
    partialProofData.publicTranscript = partialProofData.publicTranscript.concat(prog.map((op) => {
      if(typeof(op) === 'object' && 'popeq' in op) {
        return { popeq: {
          ...op.popeq,
          result: reads[i++].content,
        } };
      } else {
        return op;
      }
    }));
    if(res.events.length == 1 && res.events[0].tag === 'read') {
      return res.events[0].content;
    } else {
      return res.events;
    }
  }
}
function ledger(state) {
  const context = {
    originalState: state,
    transactionContext: new __compactRuntime.QueryContext(state, __compactRuntime.dummyContractAddress())
  };
  const partialProofData = {
    input: { value: [], alignment: [] },
    output: undefined,
    publicTranscript: [],
    privateTranscriptOutputs: []
  };
  return {
    get providerCommitment() {
      return _descriptor_0.fromValue(Contract._query(context,
                                                     partialProofData,
                                                     [
                                                      { dup: { n: 0 } },
                                                      { idx: { cached: false,
                                                               pushPath: false,
                                                               path: [
                                                                      { tag: 'value',
                                                                        value: { value: _descriptor_3.toValue(0n),
                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                      { popeq: { cached: false,
                                                                 result: undefined } }]).value);
    },
    get pricingTierCount() {
      return _descriptor_2.fromValue(Contract._query(context,
                                                     partialProofData,
                                                     [
                                                      { dup: { n: 0 } },
                                                      { idx: { cached: false,
                                                               pushPath: false,
                                                               path: [
                                                                      { tag: 'value',
                                                                        value: { value: _descriptor_3.toValue(1n),
                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                      { popeq: { cached: true,
                                                                 result: undefined } }]).value);
    },
    get totalPayments() {
      return _descriptor_2.fromValue(Contract._query(context,
                                                     partialProofData,
                                                     [
                                                      { dup: { n: 0 } },
                                                      { idx: { cached: false,
                                                               pushPath: false,
                                                               path: [
                                                                      { tag: 'value',
                                                                        value: { value: _descriptor_3.toValue(2n),
                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                      { popeq: { cached: true,
                                                                 result: undefined } }]).value);
    },
    get nullifierCount() {
      return _descriptor_2.fromValue(Contract._query(context,
                                                     partialProofData,
                                                     [
                                                      { dup: { n: 0 } },
                                                      { idx: { cached: false,
                                                               pushPath: false,
                                                               path: [
                                                                      { tag: 'value',
                                                                        value: { value: _descriptor_3.toValue(3n),
                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                      { popeq: { cached: true,
                                                                 result: undefined } }]).value);
    },
    get sequence() {
      return _descriptor_2.fromValue(Contract._query(context,
                                                     partialProofData,
                                                     [
                                                      { dup: { n: 0 } },
                                                      { idx: { cached: false,
                                                               pushPath: false,
                                                               path: [
                                                                      { tag: 'value',
                                                                        value: { value: _descriptor_3.toValue(4n),
                                                                                 alignment: _descriptor_3.alignment() } }] } },
                                                      { popeq: { cached: true,
                                                                 result: undefined } }]).value);
    }
  };
}
const _emptyContext = {
  originalState: new __compactRuntime.ContractState(),
  transactionContext: new __compactRuntime.QueryContext(new __compactRuntime.ContractState().data, __compactRuntime.dummyContractAddress())
};
const _dummyContract = new Contract({ userSecretKey: (...args) => undefined });
const pureCircuits = {
  generateNullifier: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`generateNullifier: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const secretKey_0 = args_0[0];
    const seq_0 = args_0[1];
    const tierIndex_0 = args_0[2];
    if (!(secretKey_0.buffer instanceof ArrayBuffer && secretKey_0.BYTES_PER_ELEMENT === 1 && secretKey_0.length === 32)) {
      __compactRuntime.type_error('generateNullifier',
                                  'argument 1',
                                  'vpn-payment.compact line 86 char 1',
                                  'Bytes<32>',
                                  secretKey_0)
    }
    if (!(seq_0.buffer instanceof ArrayBuffer && seq_0.BYTES_PER_ELEMENT === 1 && seq_0.length === 32)) {
      __compactRuntime.type_error('generateNullifier',
                                  'argument 2',
                                  'vpn-payment.compact line 86 char 1',
                                  'Bytes<32>',
                                  seq_0)
    }
    if (!(tierIndex_0.buffer instanceof ArrayBuffer && tierIndex_0.BYTES_PER_ELEMENT === 1 && tierIndex_0.length === 32)) {
      __compactRuntime.type_error('generateNullifier',
                                  'argument 3',
                                  'vpn-payment.compact line 86 char 1',
                                  'Bytes<32>',
                                  tierIndex_0)
    }
    return _dummyContract._generateNullifier_0(secretKey_0, seq_0, tierIndex_0);
  },
  commitmentHash: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`commitmentHash: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const data_0 = args_0[0];
    const salt_0 = args_0[1];
    if (!(data_0.buffer instanceof ArrayBuffer && data_0.BYTES_PER_ELEMENT === 1 && data_0.length === 32)) {
      __compactRuntime.type_error('commitmentHash',
                                  'argument 1',
                                  'vpn-payment.compact line 100 char 1',
                                  'Bytes<32>',
                                  data_0)
    }
    if (!(salt_0.buffer instanceof ArrayBuffer && salt_0.BYTES_PER_ELEMENT === 1 && salt_0.length === 32)) {
      __compactRuntime.type_error('commitmentHash',
                                  'argument 2',
                                  'vpn-payment.compact line 100 char 1',
                                  'Bytes<32>',
                                  salt_0)
    }
    return _dummyContract._commitmentHash_0(data_0, salt_0);
  }
};
const contractReferenceLocations = { tag: 'publicLedgerArray', indices: { } };
exports.Contract = Contract;
exports.ledger = ledger;
exports.pureCircuits = pureCircuits;
exports.contractReferenceLocations = contractReferenceLocations;
//# sourceMappingURL=index.cjs.map
