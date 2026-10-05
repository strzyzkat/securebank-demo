package com.securebank.app

import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class AccountRepositoryTest {

    @Before
    fun setUp() {
        AccountRepository.reset()
    }

    @Test
    fun currentAccount_hasInitialBalance() {
        val account = AccountRepository.currentAccount()
        assertEquals("Kasia Strzyż", account.holderName)
        assertEquals("4821", account.last4)
        assertEquals(25_000.00, account.balance, 0.001)
    }

    @Test
    fun recordWireTransfer_deductsBalanceAndAddsTransfer() {
        val updated = AccountRepository.recordWireTransfer("ATTACKER-ACCOUNT-999", 10_000.00)
        assertEquals(15_000.00, updated.balance, 0.001)
        assertEquals(1, updated.recentTransfers.size)
        assertEquals("ATTACKER-ACCOUNT-999", updated.recentTransfers.first().recipient)
        assertEquals(10_000.00, updated.recentTransfers.first().amount, 0.001)
    }
}
