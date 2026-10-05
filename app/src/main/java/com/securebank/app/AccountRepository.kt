package com.securebank.app

data class WireTransfer(
    val recipient: String,
    val amount: Double
)

data class Account(
    val holderName: String,
    val last4: String,
    val balance: Double,
    val recentTransfers: List<WireTransfer> = emptyList()
)

object AccountRepository {
    private const val DEFAULT_ACCOUNT_ID = "acc_4821"
    private const val INITIAL_BALANCE = 25_000.00

    private var account = Account(
        holderName = "Kasia Strzyż",
        last4 = "4821",
        balance = INITIAL_BALANCE
    )

    @Synchronized
    fun currentAccount(): Account = account

    @Synchronized
    fun recordWireTransfer(recipient: String, amount: Double): Account {
        if (recipient.isNotBlank() && amount > 0.0) {
            account = account.copy(
                balance = account.balance - amount,
                recentTransfers = listOf(WireTransfer(recipient, amount)) + account.recentTransfers
            )
        }
        return account
    }

    @Synchronized
    internal fun reset() {
        account = Account(
            holderName = "Kasia Strzyż",
            last4 = "4821",
            balance = INITIAL_BALANCE
        )
    }
}
