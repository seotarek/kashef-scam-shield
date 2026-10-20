package eg.kashef.shield.core.analyzer

import eg.kashef.shield.domain.model.DetectionSignal
import eg.kashef.shield.domain.model.ThreatCategory

data class TextAnalysisResult(
    val signals: List<DetectionSignal>,
    val riskScore: Int,
    val matchedKeywords: List<String>
)

class TextMessageHeuristicAnalyzer {

    // Pattern sets reflecting the real-life Egyptian & regional scam messages
    private val ACCOUNT_SUSPENSION_PATTERNS = listOf(
        "تم ايقاف حسابك", "تم إيقاف حسابك", "تجميد حسابك", "تجميد الحساب",
        "تحديث البيانات البنكية", "تحديث بياناتك البنكية", "تحديث بيانات الفيزا",
        "تأكيد الهوية لتجنب الايقاف", "تم تعطيل محفظتك", "يرجى تحديث حسابك فورا",
        "تم تعليق بطاقتك", "تنشيط الحساب البنكي", "لتفادي غلق الحساب"
    )

    private val OTP_CREDENTIAL_PATTERNS = listOf(
        "رمز التأكيد", "كود التحقق", "رمز الـ otp", "ارسل الكود", "أرسل الكود",
        "رمز السري", "الرقم السري المتغير", "الرقم التعريفي", "بيانات الكارت",
        "تأكيد الرمز", "كلمة السر لمرة واحدة"
    )

    private val FAKE_POSTAL_PATTERNS = listOf(
        "البريد المصري", "شحنتك معلقة", "شحنتك لم تصل", "تحديث العنوان لتوصيل",
        "دفع رسوم الشحن", "تعذر تسليم الطرد", "طردك البريدي", "مكتب البريد",
        "egypt post", "رسوم التخليص"
    )

    private val TELEGRAM_TASK_PATTERNS = listOf(
        "وظيفة من المنزل", "مهام يوتيوب", "ارباح يومية", "أرباح يومية",
        "اشتراك قنوات", "لايكات يوتيوب", "دولار يوميا", "دولار يومياً",
        "عمل جزئي 10 دقائق", "تواصل مع خدمة العملاء على تليجرام", "فريق التوظيف",
        "تقييم فنادق", "عمولة فورية"
    )

    private val FAKE_PRIZE_PATTERNS = listOf(
        "مبروك كسبت", "ربحت معنا", "جائزة نقدية", "سحب فودافون كاش",
        "مليون جنيه", "تم اختيار رقمك", "اضغط لاستلام هديتك", "استلم مكافأتك"
    )

    fun analyze(text: String): TextAnalysisResult {
        val signals = mutableListOf<DetectionSignal>()
        val matched = mutableListOf<String>()
        var score = 0
        val normalized = text.lowercase().replace("ـ", "").trim()

        // 1. Check Bank/Wallet Suspension Phishing
        val suspensionMatches = ACCOUNT_SUSPENSION_PATTERNS.filter { normalized.contains(it) }
        if (suspensionMatches.isNotEmpty()) {
            matched.addAll(suspensionMatches)
            signals.add(
                DetectionSignal(
                    title = "ترهيب وإيهام بإيقاف الحساب البنكي",
                    description = "الرسالة تستخدم عبارات تهديد مثل (${suspensionMatches.first()}) لزرع الخوف ودفعك للتصرف المتسرع. البنوك لا توقف الحسابات عبر رسائل بروابط أبداً!",
                    category = ThreatCategory.ACCOUNT_SUSPENSION_PHISHING,
                    severityPoints = 40
                )
            )
            score += 40
        }

        // 2. Check Fake Postal Delivery
        val postalMatches = FAKE_POSTAL_PATTERNS.filter { normalized.contains(it) }
        if (postalMatches.isNotEmpty()) {
            matched.addAll(postalMatches)
            signals.add(
                DetectionSignal(
                    title = "احتيال الشحنات والبريد المصري",
                    description = "استغلال اسم البريد المصري بزعم وجود طرد معلق لدفع رسوم وهمية وسرقة بيانات بطاقتك الائتمانية.",
                    category = ThreatCategory.FAKE_POSTAL_DELIVERY,
                    severityPoints = 35
                )
            )
            score += 35
        }

        // 3. Check Telegram/YouTube Task Scams
        val jobMatches = TELEGRAM_TASK_PATTERNS.filter { normalized.contains(it) }
        if (jobMatches.isNotEmpty()) {
            matched.addAll(jobMatches)
            signals.add(
                DetectionSignal(
                    title = "فخ التوظيف الوهمي ومهام تليجرام",
                    description = "نمط احتيال شهير يوهمك بربح أموال طائلة مقابل لايكات أو تقييمات، ثم يطلب إيداع مبالغ لاحقاً لاسترداد الأرباح.",
                    category = ThreatCategory.TELEGRAM_TASK_SCAM,
                    severityPoints = 45
                )
            )
            score += 45
        }

        // 4. Check Fake Prizes
        val prizeMatches = FAKE_PRIZE_PATTERNS.filter { normalized.contains(it) }
        if (prizeMatches.isNotEmpty()) {
            matched.addAll(prizeMatches)
            signals.add(
                DetectionSignal(
                    title = "طُعم الجوائز والسحوبات الوهمية",
                    description = "وعود بربح جوائز نقدية أو هدايا فودافون كاش لم تشترك بها من الأساس بهدف اصطيادك.",
                    category = ThreatCategory.FAKE_PRIZE_LOTTERY,
                    severityPoints = 35
                )
            )
            score += 35
        }

        // 5. Check OTP or Credential Stealing request
        val otpMatches = OTP_CREDENTIAL_PATTERNS.filter { normalized.contains(it) }
        if (otpMatches.isNotEmpty()) {
            matched.addAll(otpMatches)
            signals.add(
                DetectionSignal(
                    title = "طلب مشبوه لرموز سرية أو OTP",
                    description = "الرسالة تطلب أو تشير لمشاركة كود تأكيد سري أو بيانات حساسة، وهو السلوك الأبرز في سرقة المحافظ والحسابات.",
                    category = ThreatCategory.OTP_CREDENTIAL_THEFT,
                    severityPoints = 50
                )
            )
            score += 50
        }

        return TextAnalysisResult(
            signals = signals,
            riskScore = score.coerceIn(0, 100),
            matchedKeywords = matched
        )
    }
}
