package eg.kashef.shield.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import eg.kashef.shield.core.engine.ScamShieldEngine
import eg.kashef.shield.data.local.ScanHistoryDao
import eg.kashef.shield.data.local.ScanRecordEntity
import eg.kashef.shield.domain.model.AnalysisResult
import eg.kashef.shield.domain.model.RiskLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class UiState(
    val inputText: String = "",
    val isScanning: Boolean = false,
    val analysisResult: AnalysisResult? = null,
    val showHistoryDialog: Boolean = false
)

class MainViewModel(
    private val engine: ScamShieldEngine = ScamShieldEngine(),
    private val historyDao: ScanHistoryDao? = null
) : ViewModel() {

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    val scanHistory: StateFlow<List<ScanRecordEntity>> = (historyDao?.getAllScans() ?: flowOf(emptyList<ScanRecordEntity>()))
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList<ScanRecordEntity>())

    fun onInputChanged(newText: String) {
        _uiState.value = _uiState.value.copy(inputText = newText)
    }

    fun scanText(textToScan: String? = null) {
        val raw = textToScan ?: _uiState.value.inputText
        if (raw.isBlank()) return

        // Cap input length for performance and DOS prevention
        val target = if (raw.length > 5000) raw.substring(0, 5000) else raw

        _uiState.value = _uiState.value.copy(isScanning = true, inputText = target)

        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.Default) {
                    engine.scan(target)
                }

                _uiState.value = _uiState.value.copy(
                    isScanning = false,
                    analysisResult = result
                )

                // Save sanitized summary to local Room DB
                val snippet = if (target.length > 60) target.substring(0, 57) + "..." else target
                historyDao?.insertScan(
                    ScanRecordEntity(
                        querySnippet = snippet,
                        extractedUrl = result.extractedUrl,
                        extractedDomain = result.extractedDomain,
                        riskLevel = result.riskLevel.name,
                        riskScore = result.score,
                        headline = result.headline,
                        detailedSummary = result.detailedSummary
                    )
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isScanning = false,
                    analysisResult = AnalysisResult(
                        riskLevel = RiskLevel.SUSPICIOUS,
                        score = 25,
                        extractedUrl = null,
                        extractedDomain = null,
                        isOfficialDomain = false,
                        officialEntityName = null,
                        headline = "تعذر إكمال الفحص بدقة",
                        detailedSummary = "حدث خطأ غير متوقع أثناء معالجة النص: ${e.localizedMessage ?: "خطأ غير معروف"}.",
                        signals = emptyList(),
                        actionAdvice = listOf("تأكد من صحة الرابط وحاول مجدداً."),
                        shareableWarningText = ""
                    )
                )
            }
        }
    }

    fun clearResult() {
        _uiState.value = _uiState.value.copy(inputText = "", analysisResult = null)
    }

    fun toggleHistoryDialog(show: Boolean) {
        _uiState.value = _uiState.value.copy(showHistoryDialog = show)
    }

    fun clearAllHistory() {
        viewModelScope.launch {
            historyDao?.clearHistory()
        }
    }

    fun deleteHistoryItem(id: Long) {
        viewModelScope.launch {
            historyDao?.deleteScanById(id)
        }
    }

    class Factory(private val historyDao: ScanHistoryDao) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
                return MainViewModel(historyDao = historyDao) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}
