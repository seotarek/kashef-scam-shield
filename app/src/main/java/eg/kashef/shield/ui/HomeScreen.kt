package eg.kashef.shield.ui

import android.content.Context
import android.content.Intent
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
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
import eg.kashef.shield.domain.model.AnalysisResult
import eg.kashef.shield.domain.model.RiskLevel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: MainViewModel) {
    val state by viewModel.uiState.collectAsState()
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
                text = "كشف محاولات سرقة الحسابات، الفيزا، وانتحال البنوك والبريد محلياً وبكل سرية",
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
                        text = "مستوى الخطورة: ${result.riskLevel.arabicTitle} (${result.score}%)",
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

            // Extracted Domain Tag
            if (result.extractedDomain != null) {
                Spacer(modifier = Modifier.height(10.dp))
                AssistChip(
                    onClick = {},
                    label = { Text("النطاق المستخرج: ${result.extractedDomain}", fontSize = 12.sp) },
                    leadingIcon = { Icon(Icons.Default.Language, contentDescription = null, modifier = Modifier.size(16.dp)) }
                )
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
                    text = "ماذا تفعل الآن؟",
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

            // Viral "حذّر غيرك" Share Button
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

private fun shareWarning(context: Context, text: String) {
    val sendIntent = Intent().apply {
        action = Intent.ACTION_SEND
        putExtra(Intent.EXTRA_TEXT, text)
        type = "text/plain"
    }
    val shareIntent = Intent.createChooser(sendIntent, "مشاركة تحذير أمني عبر:")
    context.startActivity(shareIntent)
}
