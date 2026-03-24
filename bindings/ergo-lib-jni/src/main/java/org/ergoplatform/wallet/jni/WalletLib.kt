package org.ergoplatform.wallet.jni

object WalletLib {
    init {
        System.loadLibrary("ergowalletlibjni")
    }

    // Original method (kept for compatibility)
    @JvmStatic external fun addressFromTestNet(addressStr: String): Long
    @JvmStatic external fun addressDelete(address: Long)

    /**
     * Derive an Ergo P2PK address from a BIP39 mnemonic using EIP-3 path m/44'/429'/0'/0/[index].
     */
    @JvmStatic external fun mnemonicToAddress(
        mnemonic: String,
        mnemonicPass: String,
        index: Int,
        isMainnet: Boolean
    ): String

    /**
     * Build a reduced (ErgoPay-ready) transaction.
     *
     * @param inputBoxesJson JSON array of sanitized input box objects
     * @param dataInputBoxesJson JSON array of data input box objects — pass "[]" if none
     * @param outputCandidatesJson JSON array of output candidates in ergo-lib JSON format
     * @param feeNano miner fee in nanoERGs
     * @param changeAddress change address (base58)
     * @param currentHeight current blockchain height
     * @param lastBlockHeadersJson JSON array of last 10 block headers
     * @param contextExtensionsJson JSON map of {input_index: {key: hex_value}} — pass "{}" if none
     * @return base64url-encoded ReducedTransaction bytes
     */
    @JvmStatic external fun buildReducedTxBytes(
        inputBoxesJson: String,
        dataInputBoxesJson: String,
        outputCandidatesJson: String,
        feeNano: Long,
        changeAddress: String,
        currentHeight: Int,
        lastBlockHeadersJson: String,
        contextExtensionsJson: String
    ): String

    /**
     * Sign a transaction using a mnemonic.
     *
     * @param dataInputBoxesJson JSON array of data input box objects — pass "[]" if none
     * @param contextExtensionsJson JSON map of {input_index: {key: hex_value}} — pass "{}" if none
     * @param derivationCount number of EIP-3 derivation indices to derive keys for (= wallet address count)
     */
    @JvmStatic external fun signTransactionJson(
        mnemonic: String,
        mnemonicPass: String,
        inputBoxesJson: String,
        dataInputBoxesJson: String,
        outputCandidatesJson: String,
        feeNano: Long,
        changeAddress: String,
        currentHeight: Int,
        lastBlockHeadersJson: String,
        contextExtensionsJson: String,
        derivationCount: Int
    ): String
}
