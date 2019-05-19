import {
  BN,
  bufferToInt,
  ecrecover,
  rlphash,
  publicToAddress,
  ecsign,
  toBuffer,
  rlp,
  stripZeros,
  bufferToHex,
} from 'ethereumjs-util'
import Common from 'ethereumjs-common'
import { Buffer } from 'buffer'
import { TxData, TransactionOptions, TxValues, PrefixedHexString } from './types'
import { on } from 'cluster'

// secp256k1n/2
const N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16)

/**
 * An Ethereum transaction.
 */
export default class Transaction {
  // We use the ! operator here because these values are initialized in setters, and TS doesn't
  // realize that.
  private _nonce!: Buffer
  private _gasLimit!: Buffer
  private _gasPrice!: Buffer
  private _to!: Buffer
  private _value!: Buffer
  private _data!: Buffer
  private _v!: Buffer
  private _r!: Buffer
  private _s!: Buffer
  private _common: Common

  public static fromTxData(txData: TxData, opts: TransactionOptions = {}) {
    return new Transaction(
      {
        nonce: toBuffer(txData.nonce || '0x'),
        gasPrice: toBuffer(txData.gasPrice || '0x'),
        gasLimit: toBuffer(txData.gasLimit || '0x'),
        to: toBuffer(txData.to || '0x'),
        value: toBuffer(txData.value || '0x'),
        data: toBuffer(txData.data || '0x'),
        v: toBuffer(txData.v || '0x'),
        r: toBuffer(txData.r || '0x'),
        s: toBuffer(txData.s || '0x'),
      },
      opts,
    )
  }

  public static fromRlpSerializedTx(serialized: Buffer, opts: TransactionOptions = {}) {
    const values = rlp.decode(serialized)
    if (!Array.isArray(values)) {
      throw new Error('Invalid serialized tx input')
    }

    return this.fromValuesArray(values, opts)
  }

  public static fromValuesArray(values: Buffer[], opts: TransactionOptions = {}) {
    if (values.length > 9) {
      throw new Error('Invalid transaction. More values than expected were received')
    }

    return new Transaction(
      {
        nonce: values[0] || new Buffer([]),
        gasPrice: values[1] || new Buffer([]),
        gasLimit: values[2] || new Buffer([]),
        to: values[3] || new Buffer([]),
        value: values[4] || new Buffer([]),
        data: values[5] || new Buffer([]),
        v: values[6] || new Buffer([]),
        r: values[7] || new Buffer([]),
        s: values[8] || new Buffer([]),
      },
      opts,
    )
  }

  /**
   * Creates a new transaction from an object with its fields' values.
   *
   * @param values - An object with a buffer for each of the transaction's fields.
   *
   * @param opts - The transaction's options, used to indicate the chain and hardfork the
   * transactions belongs to.
   *
   * @note Transaction objects implement EIP155 by default. To disable it, use the constructor's
   * second parameter to set a chain and hardfork before EIP155 activation (i.e. before Spurious
   * Dragon.)
   */
  constructor(values: TxValues, opts: TransactionOptions = {}) {
    // instantiate Common class instance based on passed options
    if (opts.common) {
      if (opts.chain || opts.hardfork) {
        throw new Error(
          'Instantiation with both opts.common, and opts.chain and opts.hardfork parameter not allowed!',
        )
      }

      this._common = opts.common
    } else {
      const chain = opts.chain ? opts.chain : 'mainnet'
      const hardfork = opts.hardfork ? opts.hardfork : 'petersburg'

      this._common = new Common(chain, hardfork)
    }

    this.nonce = values.nonce
    this.gasPrice = values.gasPrice
    this.gasLimit = values.gasLimit
    this.to = values.to
    this.value = values.value
    this.data = values.data
    this.v = values.v
    this.r = values.r
    this.s = values.s
  }

  /**
   * If the tx's `to` is to the creation address
   */
  toCreationAddress(): boolean {
    return this.to.toString('hex') === ''
  }

  /**
   * Computes a sha3-256 hash of the serialized tx
   */
  hash(): Buffer {
    const values = [
      stripZeros(this.nonce),
      stripZeros(this.gasPrice),
      stripZeros(this.gasLimit),
      this.to,
      stripZeros(this.value),
      this.data,
      this.v,
      stripZeros(this.r),
      stripZeros(this.s),
    ]

    return rlphash(values)
  }

  getMessageToSign() {
    return this._getMessageToSign(this._unsignedTxImplementsEIP155())
  }

  getMessageToVerifySignature() {
    return this._getMessageToSign(this._signedTxImplementsEIP155())
  }

  /**
   * returns chain ID
   */
  getChainId(): number {
    return this._common.chainId()
  }

  /**
   * returns the sender's address
   */
  getSenderAddress(): Buffer {
    return publicToAddress(this.getSenderPublicKey())
  }

  /**
   * returns the public key of the sender
   */
  getSenderPublicKey(): Buffer {
    const msgHash = this.getMessageToVerifySignature()

    // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
    if (this._common.gteHardfork('homestead') && new BN(this.s).cmp(N_DIV_2) === 1) {
      throw new Error(
        'Invalid Signature: s-values greater than secp256k1n/2 are considered invalid',
      )
    }

    try {
      const v = bufferToInt(this.v)
      return ecrecover(
        msgHash,
        v,
        this.r,
        this.s,
        this._signedTxImplementsEIP155() ? this.getChainId() : undefined,
      )
    } catch (e) {
      throw new Error('Invalid Signature')
    }
  }

  /**
   * Determines if the signature is valid
   */
  verifySignature(): boolean {
    try {
      return stripZeros(this.getSenderPublicKey()).length !== 0
    } catch (e) {
      return false
    }
  }

  /**
   * sign a transaction with a given private key
   * @param privateKey - Must be 32 bytes in length
   */
  sign(privateKey: Buffer) {
    const msgHash = this.getMessageToSign()
    const sig = ecsign(msgHash, privateKey)

    if (this._unsignedTxImplementsEIP155()) {
      sig.v += this.getChainId() * 2 + 8
    }

    this.v = toBuffer(sig.v)
    this.r = sig.r
    this.s = sig.s
  }

  /**
   * The amount of gas paid for the data in this tx
   */
  getDataFee(): BN {
    const cost = new BN(0)
    for (let i = 0; i < this.data.length; i++) {
      this.data[i] === 0
        ? cost.iaddn(this._common.param('gasPrices', 'txDataZero'))
        : cost.iaddn(this._common.param('gasPrices', 'txDataNonZero'))
    }
    return cost
  }

  /**
   * the minimum amount of gas the tx must have (DataFee + TxFee + Creation Fee)
   */
  getBaseFee(): BN {
    const fee = this.getDataFee().iaddn(this._common.param('gasPrices', 'tx'))
    if (this._common.gteHardfork('homestead') && this.toCreationAddress()) {
      fee.iaddn(this._common.param('gasPrices', 'txCreation'))
    }
    return fee
  }

  /**
   * the up front amount that an account must have for this transaction to be valid
   */
  getUpfrontCost(): BN {
    return new BN(this.gasLimit).imul(new BN(this.gasPrice)).iadd(new BN(this.value))
  }

  /**
   * Validates the signature and checks to see if it has enough gas.
   */
  validate(): boolean
  validate(stringError: false): boolean
  validate(stringError: true): string
  validate(stringError: boolean = false): boolean | string {
    const errors = []
    if (!this.verifySignature()) {
      errors.push('Invalid Signature')
    }

    if (this.getBaseFee().cmp(new BN(this.gasLimit)) > 0) {
      errors.push([`gas limit is too low. Need at least ${this.getBaseFee()}`])
    }

    if (stringError) {
      return errors.join(' ')
    }

    return errors.length === 0
  }

  /**
   * Returns the rlp encoding of the transaction
   */
  serialize(): Buffer {
    const values = [
      stripZeros(this.nonce),
      stripZeros(this.gasPrice),
      stripZeros(this.gasLimit),
      this.to,
      stripZeros(this.value),
      this.data,
      this.v,
      stripZeros(this.r),
      stripZeros(this.s),
    ]

    return rlp.encode(values)
  }

  toJSON(): { [field in keyof TxValues]: PrefixedHexString } {
    return {
      nonce: bufferToHex(this.nonce),
      gasPrice: bufferToHex(this.gasPrice),
      gasLimit: bufferToHex(this.gasLimit),
      to: bufferToHex(this.to),
      value: bufferToHex(this.value),
      data: bufferToHex(this.data),
      v: bufferToHex(this.v),
      r: bufferToHex(this.r),
      s: bufferToHex(this.s),
    }
  }

  public isSigned(): boolean {
    return this.v.length > 0 && this.r.length > 0 && this.s.length > 0
  }

  get nonce(): Buffer {
    return this._nonce
  }

  set nonce(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._nonce = value
  }

  get gasPrice(): Buffer {
    return this._gasPrice
  }

  set gasPrice(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._gasPrice = value
  }

  get gasLimit(): Buffer {
    return this._gasLimit
  }

  set gasLimit(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._gasLimit = value
  }

  get to(): Buffer {
    return this._to
  }

  set to(value: Buffer) {
    this._validateIsBufferOfLengthOrEmpty(value, 20)
    this._to = value
  }

  get value(): Buffer {
    return this._value
  }

  set value(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._value = value
  }

  get data(): Buffer {
    return this._data
  }

  set data(value: Buffer) {
    this._validateIsBuffer(value)
    this._data = value
  }

  get v(): Buffer {
    return this._v
  }

  set v(value: Buffer) {
    this._validateIsBuffer(value)
    this._validateV(value)
    this._v = value
  }

  get r(): Buffer {
    return this._r
  }

  set r(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._r = value
  }

  get s(): Buffer {
    return this._s
  }

  set s(value: Buffer) {
    this._validateIsBufferOfLengthOrLess(value, 32)
    this._s = value
  }

  private _validateIsBufferOfLengthOrLess(value: any, length: number) {
    this._validateIsBuffer(value)
    const buffer = value as Buffer

    if (buffer.length > length) {
      throw new Error(`Value shouldn't have more than ${length} bytes`)
    }
  }

  private _validateIsBufferOfLengthOrEmpty(value: any, length: number) {
    this._validateIsBuffer(value)
    const buffer = value as Buffer

    if (buffer.length !== length && buffer.length !== 0) {
      throw new Error(`Value shouldn't have ${length} bytes or be empty`)
    }
  }

  private _validateIsBufferOfLength(value: any, length: number) {
    this._validateIsBuffer(value)
    const buffer = value as Buffer

    if (buffer.length !== length) {
      throw new Error(`Value shouldn't have ${length} bytes`)
    }
  }

  private _validateIsBuffer(value: any) {
    // This is here for JS users
    if (!(value instanceof Buffer)) {
      throw new Error("Value should be a buffer. Please, see ethereumjs-util's toBuffer function")
    }
  }

  private _validateV(v?: Buffer): void {
    if (v === undefined || v.length === 0) {
      return
    }

    if (!this._common.gteHardfork('spuriousDragon')) {
      return
    }

    const vInt = bufferToInt(v)

    if (vInt === 27 || vInt === 28) {
      return
    }

    const isValidEIP155V =
      vInt === this.getChainId() * 2 + 35 || vInt === this.getChainId() * 2 + 36

    if (!isValidEIP155V) {
      throw new Error(
        `Incompatible EIP155-based V ${vInt} and chain id ${this.getChainId()}. See the second parameter of the Transaction constructor to set the chain id.`,
      )
    }
  }

  private _unsignedTxImplementsEIP155() {
    return this._common.gteHardfork('spuriousDragon')
  }

  private _signedTxImplementsEIP155() {
    if (!this.isSigned()) {
      throw Error('This transaction is not signed')
    }

    const onEIP155BlockOrLater = this._common.gteHardfork('spuriousDragon')

    // EIP155 spec:
    // If block.number >= 2,675,000 and v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36, then when computing
    // the hash of a transaction for purposes of signing or recovering, instead of hashing only the first six
    // elements (i.e. nonce, gasprice, startgas, to, value, data), hash nine elements, with v replaced by
    // CHAIN_ID, r = 0 and s = 0.
    const v = bufferToInt(this.v)

    const vAndChainIdMeetEIP155Conditions =
      v === this.getChainId() * 2 + 35 || v === this.getChainId() * 2 + 36
    return vAndChainIdMeetEIP155Conditions && onEIP155BlockOrLater
  }

  private _getMessageToSign(withEIP155: boolean) {
    const values = [
      stripZeros(this.nonce),
      stripZeros(this.gasPrice),
      stripZeros(this.gasLimit),
      this.to,
      stripZeros(this.value),
      this.data,
    ]

    if (withEIP155) {
      values.push(toBuffer(this.getChainId()))
      values.push(stripZeros(toBuffer(0)))
      values.push(stripZeros(toBuffer(0)))
    }

    return rlphash(values)
  }
}
