package com.securebank.app

import android.content.ComponentName
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun useAppContext() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.securebank.app", appContext.packageName)
    }

    @Test
    fun transferMoneyActivity_isNotExported() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val activityInfo = appContext.packageManager.getActivityInfo(
            ComponentName(appContext, TransferMoneyActivity::class.java),
            0
        )
        assertFalse(activityInfo.exported)
    }
}
