package com.securebank.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import java.text.NumberFormat
import java.util.Currency

class PaymentRouterActivity : ComponentActivity() {

    private var accountState by mutableStateOf(AccountRepository.currentAccount())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Receive incoming intent from an external app
        val incomingIntent = intent

        // 2. Extract the nested "redirect" intent from extras
        val redirectIntent = incomingIntent?.let {
            IntentCompat.getParcelableExtra(it, EXTRA_ON_SUCCESS_INTENT, Intent::class.java)
        }

        // Strip dangerous URI permission flags and validate destination component
        if (redirectIntent != null) {
            redirectIntent.removeFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
            )
            val targetInfo = redirectIntent.resolveActivityInfo(packageManager, 0)
            if (targetInfo != null && targetInfo.exported && targetInfo.packageName != packageName) {
                startActivity(redirectIntent)
                finish()
                return
            }
        }

        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                Scaffold {
                    innerPadding ->
                    BankDashboardScreen(
                        account = accountState,
                        onSendSampleTransfer = ::openTransferMoneyScreen,
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        accountState = AccountRepository.currentAccount()
    }

    private fun openTransferMoneyScreen() {
        val transferIntent = Intent(this, TransferMoneyActivity::class.java).apply {
            putExtra(TransferMoneyActivity.EXTRA_RECIPIENT_ACCOUNT, SAMPLE_RECIPIENT)
            putExtra(TransferMoneyActivity.EXTRA_AMOUNT, SAMPLE_AMOUNT)
        }
        startActivity(transferIntent)
    }

    companion object {
        const val EXTRA_ON_SUCCESS_INTENT = "on_success_intent"
        private const val SAMPLE_RECIPIENT = "SAVINGS-ACCOUNT-001"
        private const val SAMPLE_AMOUNT = 100.00
    }
}

@Composable
fun BankDashboardScreen(
    account: Account,
    onSendSampleTransfer: () -> Unit,
    modifier: Modifier = Modifier
) {
    val currencyFormat = NumberFormat.getCurrencyInstance().apply {
        currency = Currency.getInstance("USD")
    }

    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = stringResource(R.string.bank_title),
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.router_subtitle),
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(16.dp))
        Text(
            text = account.holderName,
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            text = stringResource(R.string.account_masked, account.last4),
            style = MaterialTheme.typography.bodyLarge
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.balance_label, currencyFormat.format(account.balance)),
            style = MaterialTheme.typography.titleLarge
        )

        Spacer(Modifier.height(16.dp))
        Button(onClick = onSendSampleTransfer) {
            Text(stringResource(R.string.send_sample_transfer))
        }

        Spacer(Modifier.height(24.dp))
        HorizontalDivider(modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(16.dp))

        Text(
            text = stringResource(R.string.recent_transfers_title),
            style = MaterialTheme.typography.titleMedium
        )
        Spacer(Modifier.height(8.dp))

        if (account.recentTransfers.isEmpty()) {
            Text(
                text = stringResource(R.string.no_recent_transfers),
                style = MaterialTheme.typography.bodyMedium
            )
        } else {
            account.recentTransfers.forEach { transfer ->
                Text(
                    text = stringResource(
                        R.string.transfer_item,
                        currencyFormat.format(transfer.amount),
                        transfer.recipient
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }
}
