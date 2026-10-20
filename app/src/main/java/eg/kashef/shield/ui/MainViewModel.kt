package eg.kashef.shield.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import eg.kashef.shield.core.engine.ScamShieldEngine
import eg.kashef.shield.data.local.ScanHistoryDao
import eg.kashef.shield.data.local.ScanRecordEntity
import eg.kashef.shield.domain.model.AnalysisResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UiState(
    val inputText: String = "",
    val isScanning: Boolean = false,
    val analysisResult: AnalysisResult? = null,
    val showHistory: Boolean = false
)

class MainViewModel(
    private val engine: ScamShieldEngine = ScamShieldEngine(),
    private val historyDao: ScanHistoryDao? = null
) : ViewModel() {

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    fun onInputChanged(newText: String) {
        _uiState.value = _uiState.value.copy(inputText = newText)
    }

    fun scanText(textToScan: String? = null) {
        val target = textToScan ?: _uiState.value.inputText
        if (target.isBlank()) return

        _uiState.value = _uiState.value.copy(isScanning = true, inputText = target)

        viewModelScope.launch {
            val result = engine.scan(target)
            _uiState.value = _uiState.value.copy(
                isScanning = false,
                analysisResult = result
            )

            // Save to local room db history
            historyDao?.insertScan(
                ScanRecordEntity(
                    rawText = target,
                    extractedUrl = result.extractedUrl,
                    extractedDomain = result.extractedDomain,
                    riskLevel = result.riskLevel.name,
                    riskScore = result.score,
                    headline = result.headline,
                    detailedSummary = result.detailedSummary,
                    signalsJson = ""
                )
            )
        }
    }

    fun clearResult() {
        _uiState.value = _uiState.value.copy(inputText = "", analysisResult = null)
    }
}
