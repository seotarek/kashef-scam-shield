package eg.kashef.shield.core.engine

import eg.kashef.shield.core.analyzer.TextMessageHeuristicAnalyzer
import eg.kashef.shield.core.analyzer.UrlAnalysisResult
import eg.kashef.shield.core.analyzer.UrlAnalyzer
import eg.kashef.shield.domain.model.AnalysisResult
import eg.kashef.shield.domain.model.DetectionSignal
import eg.kashef.shield.domain.model.EvaluatedUrlInfo
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

        val evaluatedUrls = mutableListOf<EvaluatedUrlInfo>()
        var primaryUrlResult: UrlAnalysisResult? = null
        var maxUrlScore = -1

        for (url in extractedUrls) {
            val res = urlAnalyzer.analyze(url, surroundingText = trimmed)
            evaluatedUrls.add(
                EvaluatedUrlInfo(
                    rawUrl = res.rawUrl,
                    domain = res.canonicalDomain,
                    isOfficial = res.isOfficial,
                    officialName = res.officialEntity?.nameArabic,
                    riskScore = res.riskScore
                )
            )

            // Add URL-specific signals (excluding duplicates)
            res.signals.forEach { sig ->
                if (combinedSignals.none { it.title == sig.title }) {
                    combinedSignals.add(sig)
                }
            }

            // Pick the riskiest URL as primary; if tied, prefer the one with impersonation or first found
            if (res.riskScore > maxUrlScore || (res.riskScore == maxUrlScore && primaryUrlResult?.isOfficial == true && !res.isOfficial)) {
                maxUrlScore = res.riskScore
                primaryUrlResult = res
            }
        }

        if (primaryUrlResult == null && extractedUrls.isNotEmpty()) {
            primaryUrlResult = urlAnalyzer.analyze(extractedUrls.first(), surroundingText = trimmed)
        }

        // 1. Critical Camouflage Detection:
        // An official domain used in a message that demands OTP or threatens account suspension!
        if (primaryUrlResult != null && primaryUrlResult.isOfficial && textResult.isOtpOrCredentialThreat) {
            val officialName = primaryUrlResult.officialEntity?.nameArabic ?: "جهة رسمية"
            val camouflageSignal = DetectionSignal(
                title = "تمويه احتيالي: استغلال اسم ورابط $officialName لطلب بيانات سرية",
                description = "الرسالة تتضمن رابطاً للنطاق الرسمي لـ ($officialName)، ولكنها تطلب رمز OTP أو بيانات سرية! المؤسسات الرسمية لا تطلب رموز التحقق عبر الرسائل نهائياً.",
                category = ThreatCategory.CAMOUFLAGE_PHISHING,
                severityPoints = 60
            )
            combinedSignals.add(0, camouflageSignal)

            return AnalysisResult(
                riskLevel = RiskLevel.DANGEROUS,
                score = 85,
                extractedUrl = primaryUrlResult.rawUrl,
                extractedDomain = primaryUrlResult.canonicalDomain,
                isOfficialDomain = true,
                officialEntityName = primaryUrlResult.officialEntity?.nameArabic,
                headline = "تحذير أمني: تمويه برابط رسمي لطلب رمز سري (OTP)!",
                detailedSummary = "الرسالة تستخدم رابطاً رسمياً لـ ($officialName) كغطاء للتمويه، بينما يطلب النص مشاركة رموز سرية أو أكواد تحقق. لا تشارك أي رمز يظهر لك مع أي شخص تحت أي ظرف.",
                signals = combinedSignals,
                actionAdvice = listOf(
                    "لا تشارك رمز التأكيد (OTP) نهائياً مع أي شخص.",
                    "الموظفون الحقيقيون في البنك لن يطلبوا منك الرمز السري أبداً.",
                    "احظر رقم المرسل وتواصل مع خدمة العملاء بالرقم المطبوع على بطاقتك."
                ),
                shareableWarningText = buildShareableWarning(RiskLevel.DANGEROUS, primaryUrlResult, trimmed),
                allExtractedUrls = evaluatedUrls
            )
        }

        // 2. Official Domain without threats (True Safe)
        if (primaryUrlResult != null && primaryUrlResult.isOfficial && textResult.signals.isEmpty() && (primaryUrlResult.riskScore == 0)) {
            val entityName = primaryUrlResult.officialEntity?.nameArabic ?: "جهة معتمدة"
            return AnalysisResult(
                riskLevel = RiskLevel.SAFE,
                score = 0,
                extractedUrl = primaryUrlResult.rawUrl,
                extractedDomain = primaryUrlResult.canonicalDomain,
                isOfficialDomain = true,
                officialEntityName = primaryUrlResult.officialEntity?.nameArabic,
                headline = "نطاق رسمي مطابق ($entityName)",
                detailedSummary = "هذا الرابط يتبع رسمياً النطاق المعتمد لـ ($entityName)، ولم يتم رصد أي طلبات سرية أو مؤشرات تلاعب في المحتوى المفحوص.",
                signals = combinedSignals,
                actionAdvice = listOf(
                    "الموقع معتمد ورسمي، يمكنك الدخول بأمان.",
                    "تأكد دائماً من وجود علامة القفل (HTTPS) في شريط المتصفح."
                ),
                shareableWarningText = "",
                allExtractedUrls = evaluatedUrls
            )
        }

        // 3. Multi-URL Mixed Threat Detection:
        // If message has multiple URLs and ANY is dangerous, overall verdict is dangerous!
        val hasAnyHighRiskUrl = evaluatedUrls.any { it.riskScore >= 40 }
        val hasAnyMediumRiskUrl = evaluatedUrls.any { it.riskScore in 20..39 }

        val rawCombinedScore = textResult.riskScore + (primaryUrlResult?.riskScore ?: 0)
        val finalScore = rawCombinedScore.coerceIn(0, 100)

        val riskLevel = when {
            hasAnyHighRiskUrl || finalScore >= 50 || combinedSignals.any { 
                it.category == ThreatCategory.BRAND_IMPERSONATION || 
                it.category == ThreatCategory.OTP_CREDENTIAL_THEFT ||
                it.category == ThreatCategory.CAMOUFLAGE_PHISHING
            } -> RiskLevel.DANGEROUS
            hasAnyMediumRiskUrl || finalScore >= 25 -> RiskLevel.SUSPICIOUS
            else -> RiskLevel.SAFE
        }

        val headline = when (riskLevel) {
            RiskLevel.DANGEROUS -> {
                val brand = primaryUrlResult?.impersonatedEntity?.nameArabic
                if (brand != null) "احتيال خطير: انتحال صفة $brand!" else "تحذير: مؤشرات احتيال ونصب عالية جداً!"
            }
            RiskLevel.SUSPICIOUS -> "تنبيه: محتوى مشبوه يتطلب الحذر الشديد"
            RiskLevel.SAFE -> "طبيعي: لم تُرصد مؤشرات احتيال شائعة"
        }

        val detailedSummary = buildDetailedSummary(riskLevel, primaryUrlResult, textResult.matchedKeywords)
        val actionAdvice = buildActionAdvice(riskLevel, primaryUrlResult)
        val shareableWarning = buildShareableWarning(riskLevel, primaryUrlResult, trimmed)

        return AnalysisResult(
            riskLevel = riskLevel,
            score = if (riskLevel == RiskLevel.DANGEROUS && finalScore < 50) 65 else finalScore,
            extractedUrl = primaryUrlResult?.rawUrl,
            extractedDomain = primaryUrlResult?.canonicalDomain,
            isOfficialDomain = primaryUrlResult?.isOfficial == true,
            officialEntityName = primaryUrlResult?.officialEntity?.nameArabic,
            headline = headline,
            detailedSummary = detailedSummary,
            signals = combinedSignals,
            actionAdvice = actionAdvice,
            shareableWarningText = shareableWarning,
            allExtractedUrls = evaluatedUrls
        )
    }

    private fun buildDetailedSummary(
        level: RiskLevel,
        urlRes: UrlAnalysisResult?,
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
            RiskLevel.SAFE -> "المحتوى المفحوص لا يحتوي على علامات التصيد الشائعة، ومع ذلك احرص دائماً على عدم مشاركة أي رمز OTP مع أي شخص."
        }
    }

    private fun buildActionAdvice(level: RiskLevel, urlRes: UrlAnalysisResult?): List<String> {
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
        urlRes: UrlAnalysisResult?,
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
            shareableWarningText = "",
            allExtractedUrls = emptyList()
        )
    }
}
