package eg.kashef.shield.data.local

import android.content.Context
import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "scan_history")
data class ScanRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val querySnippet: String,
    val extractedUrl: String?,
    val extractedDomain: String?,
    val riskLevel: String,
    val riskScore: Int,
    val headline: String,
    val detailedSummary: String
)

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 50")
    fun getAllScans(): Flow<List<ScanRecordEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(record: ScanRecordEntity): Long

    @Query("DELETE FROM scan_history WHERE id = :id")
    suspend fun deleteScanById(id: Long)

    @Query("DELETE FROM scan_history")
    suspend fun clearHistory()
}

@Database(entities = [ScanRecordEntity::class], version = 2, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanHistoryDao(): ScanHistoryDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "kashef_scan_history.db"
                ).fallbackToDestructiveMigration().build()
                INSTANCE = instance
                instance
            }
        }
    }
}
