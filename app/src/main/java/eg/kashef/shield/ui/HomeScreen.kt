package eg.kashef.shield.ui

import android.content.Context
import android.content.Intent
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import eg.kashef.shield.data.local.ScanRecordEntity
import eg.kashef.shield.domain.model.AnalysisResult
import eg.kashef.shield.domain.model.EvaluatedUrlInfo
import eg.kashef.shield.domain.model.RiskLevel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: MainViewModel) {
    val state by viewModel.uiState.collectAsState()
    val historyList by viewModel.scanHistory.collectAsState()
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val scrollState = rememberScrollState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = "Kashef Logo",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "كاشف | درع الاحتيال",
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.toggleHistoryDialog(true) }) {
                        Icon(Icons.Default.History, contentDescription = "سجل الفحوصات")
                    }
                    IconButton(onClick = { viewModel.clearResult() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "تفريغ")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(scrollState)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Header Intro
            Text(
                text = "افحص أي رابط أو رسالة مشبوهة فوراً",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
            Text(
                text = "فحص محلي آمن 100% دون إرسال بياناتك لأي سيرفر لحمايتك من سرقة الحسابات وانتحال البنوك",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
            )

            // Input Card
            OutlinedCard(
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    OutlinedTextField(
                        value = state.inputText,
                        onValueChange = { viewModel.onInputChanged(it) },
                        placeholder = { Text("الصق نص الرسالة أو الرابط هنا...") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 110.dp),
                        shape = RoundedCornerShape(12.dp)
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            onClick = {
                                val clip = clipboardManager.getText()?.text
                                if (!clip.isNullOrBlank()) {
                                    viewModel.onInputChanged(clip)
                                    viewModel.scanText(clip)
                                }
                            }
                        ) {
                            Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("لصق وفحص")
                        }

                        Button(
                            onClick = { viewModel.scanText() },
                            enabled = state.inputText.isNotBlank() && !state.isScanning,
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            if (state.isScanning) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    color = MaterialTheme.colorScheme.onPrimary,
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Icon(Icons.Default.Search, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("فحص فوري")
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Analysis Result Presentation
            AnimatedVisibility(
                visible = state.analysisResult != null,
                enter = fadeIn() + expandVertically()
            ) {
                state.analysisResult?.let { result ->
                    ResultCard(result = result, onShareWarning = { shareWarning(context, it) })
                }
            }
        }
    }

    // History Dialog
    if (state.showHistoryDialog) {
        HistoryDialog(
            historyList = historyList,
            onDismiss = { viewModel.toggleHistoryDialog(false) },
            onClearAll = { viewModel.clearAllHistory() },
            onDeleteItem = { viewModel.deleteHistoryItem(it) }
        )
    }
}

@Composable
fun ResultCard(result: AnalysisResult, onShareWarning: (String) -> Unit) {
    val (cardColor, textColor, icon) = when (result.riskLevel) {
        RiskLevel.SAFE -> Triple(Color(0xFFE8F5E9), Color(0xFF2E7D32), Icons.Default.CheckCircle)
        RiskLevel.SUSPICIOUS -> Triple(Color(0xFFFFF8E1), Color(0xFFF57F17), Icons.Default.Warning)
        RiskLevel.DANGEROUS -> Triple(Color(0xFFFFEBEE), Color(0xFFC62828), Icons.Default.GppBad)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = cardColor),
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            // Header Row
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = textColor,
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = result.headline,
                        fontWeight = FontWeight.Bold,
                        fontSize = 17.sp,
                        color = textColor
                    )
                    Text(
                        text = "التقييم: ${result.riskLevel.arabicTitle} (${result.score}%)",
                        fontSize = 13.sp,
                        color = textColor.copy(alpha = 0.85f)
                    )
                }
            }

            HorizontalDivider(
                modifier = Modifier.padding(vertical = 14.dp),
                color = textColor.copy(alpha = 0.2f)
            )

            // Detailed Explanation
            Text(
                text = result.detailedSummary,
                fontSize = 14.sp,
                lineHeight = 22.sp,
                color = Color(0xFF1E293B)
            )

            // Multi-URL or Single-URL Badges
            if (result.allExtractedUrls.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = if (result.allExtractedUrls.size > 1) "الروابط المفحوصة (${result.allExtractedUrls.size}):" else "النطاق المستخرج:",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = Color(0xFF0F172A)
                )
                result.allExtractedUrls.forEach { urlInfo ->
                    val badgeColor = when {
                        urlInfo.riskScore >= 40 -> Color(0xFFC62828)
                        urlInfo.riskScore >= 20 -> Color(0xFFF57F17)
                        urlInfo.isOfficial -> Color(0xFF2E7D32)
                        else -> Color(0xFF475569)
                    }
                    AssistChip(
                        onClick = {},
                        label = { Text("${urlInfo.domain} ${urlInfo.officialName?.let { "($it)" } ?: ""}", fontSize = 12.sp, color = badgeColor) },
                        leadingIcon = { Icon(Icons.Default.Language, contentDescription = null, modifier = Modifier.size(16.dp), tint = badgeColor) },
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            // Signals / Red Flags
            if (result.signals.isNotEmpty()) {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "المؤشرات المرصودة:",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = Color(0xFF0F172A)
                )
                result.signals.forEach { signal ->
                    Row(
                        modifier = Modifier.padding(top = 6.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text("• ", fontWeight = FontWeight.Bold, color = textColor)
                        Column {
                            Text(text = signal.title, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = textColor)
                            Text(text = signal.description, fontSize = 12.sp, color = Color(0xFF334155))
                        }
                    }
                }
            }

            // Action Advice
            if (result.actionAdvice.isNotEmpty()) {
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = "الإجراء الموصى به:",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = Color(0xFF0F172A)
                )
                result.actionAdvice.forEach { advice ->
                    Text(
                        text = "✓ $advice",
                        fontSize = 13.sp,
                        color = Color(0xFF1E293B),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            // Viral Share Button
            if (result.riskLevel != RiskLevel.SAFE && result.shareableWarningText.isNotBlank()) {
                Spacer(modifier = Modifier.height(18.dp))
                Button(
                    onClick = { onShareWarning(result.shareableWarningText) },
                    colors = ButtonDefaults.buttonColors(containerColor = textColor),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, tint = Color.White)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "حذّر أصحابك وعائلتك على واتساب",
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun HistoryDialog(
    historyList: List<ScanRecordEntity>,
    onDismiss: () -> Unit,
    onClearAll: () -> Unit,
    onDeleteItem: (Long) -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.8f)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "سجل الفحوصات المحلية",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "إغلاق")
                    }
                }

                Text(
                    text = "سجل الفحوصات محفوظ محلياً على جهازك فقط لحمايتك.",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp))

                if (historyList.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "لا توجد فحوصات سابقة",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 14.sp
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.weight(1f)
                    ) {
                        items(historyList, key = { it.id }) { item ->
                            val levelColor = when (item.riskLevel) {
                                "DANGEROUS" -> Color(0xFFC62828)
                                "SUSPICIOUS" -> Color(0xFFF57F17)
                                else -> Color(0xFF2E7D32)
                            }
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                shape = RoundedCornerShape(12.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                                )
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = item.headline,
                                            fontWeight = FontWeight.SemiBold,
                                            fontSize = 14.sp,
                                            color = levelColor
                                        )
                                        Text(
                                            text = item.querySnippet,
                                            fontSize = 12.sp,
                                            color = MaterialTheme.colorScheme.onSurface,
                                            maxLines = 1
                                        )
                                        Text(
                                            text = dateFormat.format(Date(item.timestamp)),
                                            fontSize = 11.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    IconButton(onClick = { onDeleteItem(item.id) }) {
                                        Icon(
                                            Icons.Default.Delete,
                                            contentDescription = "حذف",
                                            tint = MaterialTheme.colorScheme.error,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedButton(
                        onClick = onClearAll,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Default.DeleteSweep, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("مسح السجل بالكامل")
                    }
                }
            }
        }
    }
}

private fun shareWarning(context: Context, text: String) {
    val sendIntent = Intent().apply {
        action = Intent.ACTION_SEND
        putExtra(Intent.EXTRA_TEXT, text)
        type = "text/plain"
    }
    val shareIntent = Intent.createChooser(sendIntent, "مشاركة تحذير أمني عبر:")
    context.startActivity(shareIntent)
}
