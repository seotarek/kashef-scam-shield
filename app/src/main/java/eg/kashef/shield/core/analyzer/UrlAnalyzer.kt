package eg.kashef.shield.core.analyzer

import eg.kashef.shield.core.util.ArabicTextNormalizer
import eg.kashef.shield.core.whitelist.EgyptianEntitiesWhitelist
import eg.kashef.shield.core.whitelist.OfficialEntity
import eg.kashef.shield.domain.model.DetectionSignal
import eg.kashef.shield.domain.model.ThreatCategory
import java.net.URI
import java.util.Locale
import java.util.regex.Pattern

data class UrlAnalysisResult(
    val rawUrl: String,
    val canonicalDomain: String,
    val isOfficial: Boolean,
    val officialEntity: OfficialEntity?,
    val impersonatedEntity: OfficialEntity?,
    val signals: List<DetectionSignal>,
    val riskScore: Int
)

class UrlAnalyzer {

    companion object {
        // High-risk cheap TLDs frequently abused in phishing campaigns
        private val HIGH_RISK_TLDS = setOf(
            "xyz", "top", "site", "fun", "buzz", "space", "club", "work",
            "icu", "vip", "live", "loan", "cfd", "rest", "click", "online",
            "cc", "tk", "ml", "ga", "cf", "gq", "surf", "monster", "cam"
        )

        // Known link shorteners
        private val SHORTENER_DOMAINS = setOf(
            "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "shorturl.at", "is.gd",
            "rb.gy", "rebrand.ly", "ow.ly", "buff.ly", "goo.gl"
        )

        private val IPV4_PATTERN = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        private val URL_REGEX = Pattern.compile(
            "(?i)\\b(?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\((?:[^\\s()<>]+|(?:\\([^\\s()<>]+\\)))*\\))+(?:\\((?:[^\\s()<>]+|(?:\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’])"
        )

        private val REDIRECT_PARAM_PATTERN = Pattern.compile(
            "(?i)[?&](?:url|redirect|redirect_to|next|target|dest|to)=https?%3A%2F%2F|(?i)[?&](?:url|redirect|redirect_to|next|target|dest|to)=https?://"
        )
    }

    fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = URL_REGEX.matcher(text)
        while (matcher.find()) {
            var url = matcher.group()
            if (!url.startsWith("http://", ignoreCase = true) && !url.startsWith("https://", ignoreCase = true)) {
                url = "https://$url"
            }
            urls.add(url)
        }
        return urls
    }

    fun analyze(rawUrl: String, surroundingText: String = ""): UrlAnalysisResult {
        val signals = mutableListOf<DetectionSignal>()
        var score = 0

        val canonicalDomain = extractCanonicalDomain(rawUrl)
        val officialEntity = EgyptianEntitiesWhitelist.findOfficialEntityByDomain(canonicalDomain)

        // 1. Check for open redirect tricks even on official or popular domains
        if (REDIRECT_PARAM_PATTERN.matcher(rawUrl).find()) {
            signals.add(
                DetectionSignal(
                    title = "إعادة توجيه مشبوهة (Open Redirect)",
                    description = "الرابط يحتوي على بارامتر إعادة توجيه قد يُستغل لتحويلك لصفحة خارجية خبيثة بعد فتح النطاق الظاهر.",
                    category = ThreatCategory.SUSPICIOUS_SHORTENER,
                    severityPoints = 35
                )
            )
            score += 35
        }

        if (officialEntity != null) {
            // Whitelisted official Egyptian institution
            signals.add(
                DetectionSignal(
                    title = "نطاق رسمي موثق ومطابق",
                    description = "هذا النطاق يتبع رسمياً لـ: ${officialEntity.nameArabic}",
                    category = ThreatCategory.OFFICIAL_VERIFIED,
                    severityPoints = 0
                )
            )
            return UrlAnalysisResult(
                rawUrl = rawUrl,
                canonicalDomain = canonicalDomain,
                isOfficial = true,
                officialEntity = officialEntity,
                impersonatedEntity = null,
                signals = signals,
                riskScore = score
            )
        }

        // 2. Direct IP Address Check
        if (IPV4_PATTERN.matcher(canonicalDomain).matches()) {
            signals.add(
                DetectionSignal(
                    title = "رابط عنوان IP مباشر",
                    description = "الموقع يستخدم عنوان IP رقمي مباشر ($canonicalDomain) بدلاً من اسم نطاق رسمي، وهذا أسلوب خبيث لتجنب الحظر.",
                    category = ThreatCategory.DIRECT_IP_ADDRESS,
                    severityPoints = 40
                )
            )
            score += 40
        }

        // 3. High-Risk TLD Check
        val tld = canonicalDomain.substringAfterLast('.', "")
        if (HIGH_RISK_TLDS.contains(tld)) {
            signals.add(
                DetectionSignal(
                    title = "نطاق إنترنت رخيص ومشبوه (.$tld)",
                    description = "ينتهي الرابط بنطاق (.$tld)، وهي نطاقات رخيصة التكلفة تُستخدم بكثرة في إنشاء صفحات احتيال مؤقتة.",
                    category = ThreatCategory.HIGH_RISK_TLD,
                    severityPoints = 30
                )
            )
            score += 30
        }

        // 4. Brand Impersonation / Typosquatting in Domain or Full URL
        val normalizedSurrounding = ArabicTextNormalizer.normalize(surroundingText)
        val impersonated = EgyptianEntitiesWhitelist.findBrandImpersonated(canonicalDomain)
            ?: EgyptianEntitiesWhitelist.findBrandImpersonated(rawUrl)
            ?: EgyptianEntitiesWhitelist.findBrandImpersonated(normalizedSurrounding)

        if (impersonated != null) {
            val isBrandInDomain = EgyptianEntitiesWhitelist.findBrandImpersonated(canonicalDomain) != null
            if (isBrandInDomain) {
                signals.add(
                    DetectionSignal(
                        title = "انتحال وتزوير صريح: ${impersonated.nameArabic}",
                        description = "الرابط يحتوي على اسم (${impersonated.nameArabic}) لكنه مسجل على سيرفر مزيف ($canonicalDomain) ولا يتبع الدومين الرسمي المعتمد (${impersonated.primaryDomain})!",
                        category = ThreatCategory.BRAND_IMPERSONATION,
                        severityPoints = 50
                    )
                )
                score += 50
            } else if (surroundingText.isNotBlank()) {
                // The message talks about the bank/wallet, but the link is to a completely unrelated external domain!
                signals.add(
                    DetectionSignal(
                        title = "رابط مريب غير متطابق مع نص الرسالة",
                        description = "الرسالة تتحدث باسم (${impersonated.nameArabic})، بينما يوجهك الرابط لموقع خارجي غريب كلياً ($canonicalDomain)!",
                        category = ThreatCategory.BRAND_IMPERSONATION,
                        severityPoints = 45
                    )
                )
                score += 45
            }
        }

        // 5. URL Shortener Masking
        if (SHORTENER_DOMAINS.contains(canonicalDomain)) {
            signals.add(
                DetectionSignal(
                    title = "رابط مختصر لإخفاء الوجهة الحقيقية",
                    description = "الرابط يستخدم خدمة اختصار روابط ($canonicalDomain) بهدف إخفاء الدومين الحقيقي الذي سيتم تحويلك إليه.",
                    category = ThreatCategory.SUSPICIOUS_SHORTENER,
                    severityPoints = 25
                )
            )
            score += 25
        }

        // 6. Deceptive Subdomain Trick (e.g. nbe.com.eg.login-account.site)
        val parts = canonicalDomain.split(".")
        if (parts.size >= 3) {
            val suspiciousSub = parts.subList(0, parts.size - 2).joinToString(".")
            if (EgyptianEntitiesWhitelist.findBrandImpersonated(suspiciousSub) != null) {
                signals.add(
                    DetectionSignal(
                        title = "خدعة النطاق الفرعي (Subdomain Spoofing)",
                        description = "تم وضع اسم المؤسسة في بداية العنوان لإيهامك بالمصداقية، بينما الموقع الحقيقي ينتهي بنطاق مختلف كلياً.",
                        category = ThreatCategory.TYPOSQUATTING_DOMAIN,
                        severityPoints = 40
                    )
                )
                score += 40
            }
        }

        return UrlAnalysisResult(
            rawUrl = rawUrl,
            canonicalDomain = canonicalDomain,
            isOfficial = false,
            officialEntity = null,
            impersonatedEntity = impersonated,
            signals = signals,
            riskScore = score.coerceIn(0, 100)
        )
    }

    private fun extractCanonicalDomain(rawUrl: String): String {
        return try {
            val uri = URI(if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) "https://$rawUrl" else rawUrl)
            var host = uri.host ?: ""
            if (host.startsWith("www.", ignoreCase = true)) {
                host = host.substring(4)
            }
            host.lowercase(Locale.ROOT)
        } catch (_: Exception) {
            rawUrl.substringAfter("://").substringBefore("/").substringBefore("?").removePrefix("www.").lowercase()
        }
    }
}
