package eg.kashef.shield

import android.app.Application
import eg.kashef.shield.data.local.AppDatabase

class KashefApp : Application() {

    val database: AppDatabase by lazy {
        AppDatabase.getInstance(this)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    companion object {
        lateinit var instance: KashefApp
            private set
    }
}
