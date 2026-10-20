package eg.kashef.shield.core.engine

import eg.kashef.shield.core.analyzer.TextMessageHeuristicAnalyzer
import eg.kashef.shield.core.analyzer.UrlAnalyzer
import eg.kashef.shield.domain.model.AnalysisResult
import eg.kashef.shield.domain.model.DetectionSignal
import eg.kashef.shield.domain.model.RiskLevel
import eg.kashef.shield.domain.model.ThreatCategory

class ScamShieldEngine(
    private val urlAnalyzer: UrlAnalyzer = UrlAnalyzer(),
    private val textAnalyzer: TextMessageHeuristicAnalyzer = TextMessageHeuristicAnalyzer()
) {

    fun scan(rawInput: String): AnalysisResult {
        val trimmed = rawInput.trim()
        if (trimmed.isBlank()) {
            return emptyResult()
        }

        val extractedUrls = urlAnalyzer.extractUrls(trimmed)
        val textResult = textAnalyzer.analyze(trimmed)

        val combinedSignals = mutableListOf<DetectionSignal>()
        combinedSignals.addAll(textResult.signals)

        var highestUrlScore = 0
        var primaryUrlResult = if (extractedUrls.isNotEmpty()) {
            urlAnalyzer.analyze(extractedUrls.first(), surroundingText = trimmed)
        } else null

        // If multiple URLs, analyze all and pick the riskiest
        for (url in extractedUrls) {
            val res = urlAnalyzer.analyze(url, surroundingText = trimmed)
            if (res.riskScore >= highestUrlScore) {
                highestUrlScore = res.riskScore
                primaryUrlResult = res
            }
        }

        primaryUrlResult?.signals?.let { combinedSignals.addAll(it) }

        // Whitelist check
        if (primaryUrlResult != null && primaryUrlResult.isOfficial && textResult.riskScore < 20) {
            return AnalysisResult(
                riskLevel = RiskLevel.SAFE,
                score = 0,
                extractedUrl = primaryUrlResult.rawUrl,
                extractedDomain = primaryUrlResult.canonicalDomain,
                isOfficialDomain = true,
                officialEntityName = primaryUrlResult.officialEntity?.nameArabic,
                headline = "رابط رسمي موثوق (${primaryUrlResult.officialEntity?.nameArabic})",
                detailedSummary = "هذا الرابط يتبع رسمياً النطاق المعتمد لـ (${primaryUrlResult.officialEntity?.nameArabic})، ولم يتم رصد أي محاولات تلاعب أو انتحال.",
                signals = combinedSignals,
                actionAdvice = listOf(
                    "الموقع معتمد ورسمي، يمكنك الدخول بأمان.",
                    "تأكد دائماً من وجود علامة القفل (HTTPS) في شريط المتصفح."
                ),
                shareableWarningText = ""
            )
        }

        val rawCombinedScore = textResult.riskScore + (primaryUrlResult?.riskScore ?: 0)
        val finalScore = rawCombinedScore.coerceIn(0, 100)

        val riskLevel = when {
            finalScore >= 50 || combinedSignals.any { it.category == ThreatCategory.BRAND_IMPERSONATION || it.category == ThreatCategory.OTP_CREDENTIAL_THEFT } -> RiskLevel.DANGEROUS
            finalScore >= 25 -> RiskLevel.SUSPICIOUS
            else -> RiskLevel.SAFE
        }

        val headline = when (riskLevel) {
            RiskLevel.DANGEROUS -> {
                val brand = primaryUrlResult?.impersonatedEntity?.nameArabic
                if (brand != null) "احتيال خطير: انتحال صفة $brand!" else "تحذير: مؤشرات احتيال ونصب عالية جداً!"
            }
            RiskLevel.SUSPICIOUS -> "تنبيه: محتوى مشبوه يتطلب الحذر الشديد"
            RiskLevel.SAFE -> "لم يتم رصد مؤشرات احتيال واضحة"
        }

        val detailedSummary = buildDetailedSummary(riskLevel, primaryUrlResult, textResult.matchedKeywords)
        val actionAdvice = buildActionAdvice(riskLevel, primaryUrlResult)
        val shareableWarning = buildShareableWarning(riskLevel, primaryUrlResult, trimmed)

        return AnalysisResult(
            riskLevel = riskLevel,
            score = finalScore,
            extractedUrl = primaryUrlResult?.rawUrl,
            extractedDomain = primaryUrlResult?.canonicalDomain,
            isOfficialDomain = false,
            officialEntityName = null,
            headline = headline,
            detailedSummary = detailedSummary,
            signals = combinedSignals,
            actionAdvice = actionAdvice,
            shareableWarningText = shareableWarning
        )
    }

    private fun buildDetailedSummary(
        level: RiskLevel,
        urlRes: eg.kashef.shield.core.analyzer.UrlAnalysisResult?,
        matchedKeywords: List<String>
    ): String {
        return when (level) {
            RiskLevel.DANGEROUS -> {
                val domain = urlRes?.canonicalDomain ?: "الرابط"
                val impersonated = urlRes?.impersonatedEntity?.nameArabic
                if (impersonated != null) {
                    "الرسالة تحاول إيهامك بأنها من جهة رسمية ($impersonated)، لكنها توجهك لنطاق احتيالي مزيف ($domain). هدف هذه الصفحة هو سرقة أرقام البطاقات الائتمانية أو كلمات المرور."
                } else {
                    "تم رصد أساليب احتيال واضحة ونطاقات غير موثوقة. لا تقم بالضغط على الرابط أو إدخال أي أرقام سرية أو بيانات بنكية نهائياً."
                }
            }
            RiskLevel.SUSPICIOUS -> "هناك عبارات ضغط واستعجال ونطاقات غير شائعة في الرسالة. ننصح بعدم إدخال أي بيانات شخصية والتأكد من الجهة المصدرية عبر قنواتها الرسمية."
            RiskLevel.SAFE -> "النص والرابط لا يحتويان على علامات التصيد الشائعة، ومع ذلك احرص دائماً على عدم مشاركة أي رمز OTP مع أي شخص."
        }
    }

    private fun buildActionAdvice(level: RiskLevel, urlRes: eg.kashef.shield.core.analyzer.UrlAnalysisResult?): List<String> {
        return when (level) {
            RiskLevel.DANGEROUS -> listOf(
                "لا تضغط على الرابط ولا تفتحه في المتصفح.",
                "لا تشارك أي رمز سري (OTP) أو كود تأكيد مع أي شخص تحت أي ظرف.",
                "البنوك والشركات الرسمية لا تطلب تحديث الحسابات عبر رسائل بروابط.",
                "احظر رقم المرسل فوراً وأبلغ عنه."
            )
            RiskLevel.SUSPICIOUS -> listOf(
                "تأكد من هوية المرسل وتواصل مع خدمة العملاء بالرقم الرسمي المسجل على ظهر بطاقتك.",
                "تجنب تسجيل الدخول أو إدخال بيانات الدفع على صفحات غير معروفة."
            )
            RiskLevel.SAFE -> listOf(
                "الرابط يبدو طبيعياً، لكن تذكر دائماً ألا تعطي كلمة السر أو OTP لأحد."
            )
        }
    }

    private fun buildShareableWarning(
        level: RiskLevel,
        urlRes: eg.kashef.shield.core.analyzer.UrlAnalysisResult?,
        originalText: String
    ): String {
        if (level == RiskLevel.SAFE) return ""
        val target = urlRes?.canonicalDomain ?: "هذا الرابط"
        val brand = urlRes?.impersonatedEntity?.nameArabic?.let { "باسم ($it)" } ?: ""

        return """
⚠️ تحذير أمني عاجل!
تم رصد محاولة نصب واحتيال إلكتروني $brand عبر الرابط المزيف:
🔗 $target

نرجو الحذر وعدم فتح الرابط أو مشاركة أي بيانات بنكية أو رموز سرية (OTP).
تم الفحص والتحقق عبر تطبيق كاشف (Kashef Anti-Scam Shield).
احمِ غيرك وشارك التحذير!
        """.trimIndent()
    }

    private fun emptyResult(): AnalysisResult {
        return AnalysisResult(
            riskLevel = RiskLevel.SAFE,
            score = 0,
            extractedUrl = null,
            extractedDomain = null,
            isOfficialDomain = false,
            officialEntityName = null,
            headline = "في انتظار الفحص",
            detailedSummary = "انسخ أي رسالة أو رابط مشبوه أو شاركه مع التطبيق للبدء فوراً.",
            signals = emptyList(),
            actionAdvice = emptyList(),
            shareableWarningText = ""
        )
    }
}
