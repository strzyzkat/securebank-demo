package com.securebank.app

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import java.text.NumberFormat
import java.util.Currency

class TransferMoneyActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Reads transfer parameters from the launching intent
        val recipient = intent.getStringExtra(EXTRA_RECIPIENT_ACCOUNT).orEmpty()
        val amount = intent.getDoubleExtra(EXTRA_AMOUNT, 0.0)

        // Executes the transaction inside SecureBank's process context
        executeWireTransfer(recipient, amount)

        val formattedAmount = NumberFormat.getCurrencyInstance().apply {
            currency = Currency.getInstance("USD")
        }.format(amount)

        Toast.makeText(
            this,
            getString(R.string.transfer_completed, formattedAmount, recipient),
            Toast.LENGTH_LONG
        ).show()

        finish()
    }

    private fun executeWireTransfer(recipient: String, amount: Double) {
        AccountRepository.recordWireTransfer(recipient, amount)
    }

    companion object {
        const val EXTRA_RECIPIENT_ACCOUNT = "recipient_account"
        const val EXTRA_AMOUNT = "amount"
    }
}
