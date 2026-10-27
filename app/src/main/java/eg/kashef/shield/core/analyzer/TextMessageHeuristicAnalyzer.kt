package eg.kashef.shield.core.analyzer

import eg.kashef.shield.core.util.ArabicTextNormalizer
import eg.kashef.shield.domain.model.DetectionSignal
import eg.kashef.shield.domain.model.ThreatCategory

data class TextAnalysisResult(
    val signals: List<DetectionSignal>,
    val riskScore: Int,
    val matchedKeywords: List<String>,
    val isOtpOrCredentialThreat: Boolean,
    val isAccountSuspensionThreat: Boolean
)

class TextMessageHeuristicAnalyzer {

    // Raw patterns - will be normalized via ArabicTextNormalizer
    private val RAW_ACCOUNT_SUSPENSION_PATTERNS = listOf(
        "تم ايقاف حسابك", "تم إيقاف حسابك", "تجميد حسابك", "تجميد الحساب",
        "تحديث البيانات البنكية", "تحديث بياناتك البنكية", "تحديث بيانات الفيزا",
        "تأكيد الهوية لتجنب الايقاف", "تم تعطيل محفظتك", "يرجى تحديث حسابك فورا",
        "تم تعليق بطاقتك", "تنشيط الحساب البنكي", "لتفادي غلق الحساب",
        "ايقاف بطاقتك الائتمانية", "تحديث بيانات الحساب البنكي", "اغلاق حسابك خلال 24 ساعة"
    )

    private val RAW_OTP_CREDENTIAL_PATTERNS = listOf(
        "رمز التأكيد", "كود التحقق", "رمز الـ otp", "ارسل الكود", "أرسل الكود",
        "رمز السري", "الرقم السري المتغير", "الرقم التعريفي", "بيانات الكارت",
        "تأكيد الرمز", "كلمة السر لمرة واحدة", "cvv", "رمز الامان", "الرقم السري للبطاقة"
    )

    private val RAW_FAKE_POSTAL_PATTERNS = listOf(
        "البريد المصري", "شحنتك معلقة", "شحنتك لم تصل", "تحديث العنوان لتوصيل",
        "دفع رسوم الشحن", "تعذر تسليم الطرد", "طردك البريدي", "مكتب البريد",
        "egypt post", "رسوم التخليص", "تحديث بيانات الشحنة"
    )

    private val RAW_TELEGRAM_TASK_PATTERNS = listOf(
        "وظيفة من المنزل", "مهام يوتيوب", "ارباح يومية", "أرباح يومية",
        "اشتراك قنوات", "لايكات يوتيوب", "دولار يوميا", "دولار يومياً",
        "عمل جزئي 10 دقائق", "تواصل مع خدمة العملاء على تليجرام", "فريق التوظيف",
        "تقييم فنادق", "عمولة فورية", "ارباح بالدولار"
    )

    private val RAW_FAKE_PRIZE_PATTERNS = listOf(
        "مبروك كسبت", "ربحت معنا", "جائزة نقدية", "سحب فودافون كاش",
        "مليون جنيه", "تم اختيار رقمك", "اضغط لاستلام هديتك", "استلم مكافأتك",
        "ربحت جائزة مالية", "مبروك فزت"
    )

    // Awareness patterns (to avoid false-positive panic when user checks official bank safety alerts)
    private val RAW_AWARENESS_PATTERNS = listOf(
        "احذر من", "تحذير أمني", "لا تشارك", "لن يطلب منك", "تنبيه هام", "احترس من"
    )

    // Pre-normalized pattern sets for O(1) text matching
    private val normalizedSuspension = RAW_ACCOUNT_SUSPENSION_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()
    private val normalizedOtp = RAW_OTP_CREDENTIAL_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()
    private val normalizedPostal = RAW_FAKE_POSTAL_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()
    private val normalizedTelegram = RAW_TELEGRAM_TASK_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()
    private val normalizedPrizes = RAW_FAKE_PRIZE_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()
    private val normalizedAwareness = RAW_AWARENESS_PATTERNS.map { ArabicTextNormalizer.normalize(it) }.distinct()

    fun analyze(text: String): TextAnalysisResult {
        val signals = mutableListOf<DetectionSignal>()
        val matched = mutableListOf<String>()
        var score = 0

        val normalized = ArabicTextNormalizer.normalize(text)
        if (normalized.isBlank()) {
            return TextAnalysisResult(emptyList(), 0, emptyList(), isOtpOrCredentialThreat = false, isAccountSuspensionThreat = false)
        }

        val isAwarenessMessage = normalizedAwareness.any { normalized.contains(it) }

        // 1. Check Bank/Wallet Suspension Phishing
        var hasSuspension = false
        val suspensionMatches = normalizedSuspension.filter { normalized.contains(it) }
        if (suspensionMatches.isNotEmpty()) {
            hasSuspension = true
            matched.addAll(suspensionMatches)
            val points = if (isAwarenessMessage) 10 else 40
            signals.add(
                DetectionSignal(
                    title = "ترهيب وإيهام بإيقاف الحساب البنكي",
                    description = "الرسالة تستخدم عبارات ترهيب مثل (${suspensionMatches.first()}) لدفعك للتصرف المتسرع. البنوك الرسمية لا توقف الحسابات عبر رسائل بروابط أبداً.",
                    category = ThreatCategory.ACCOUNT_SUSPENSION_PHISHING,
                    severityPoints = points
                )
            )
            score += points
        }

        // 2. Check Fake Postal Delivery
        val postalMatches = normalizedPostal.filter { normalized.contains(it) }
        if (postalMatches.isNotEmpty()) {
            matched.addAll(postalMatches)
            val points = if (isAwarenessMessage) 10 else 35
            signals.add(
                DetectionSignal(
                    title = "احتيال الشحنات والبريد المصري",
                    description = "استغلال اسم البريد المصري بزعم وجود طرد معلق لدفع رسوم وهمية وسرقة بيانات بطاقتك الائتمانية.",
                    category = ThreatCategory.FAKE_POSTAL_DELIVERY,
                    severityPoints = points
                )
            )
            score += points
        }

        // 3. Check Telegram/YouTube Task Scams
        val jobMatches = normalizedTelegram.filter { normalized.contains(it) }
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
        val prizeMatches = normalizedPrizes.filter { normalized.contains(it) }
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
        var hasOtp = false
        val otpMatches = normalizedOtp.filter { normalized.contains(it) }
        if (otpMatches.isNotEmpty()) {
            hasOtp = true
            matched.addAll(otpMatches)
            val points = if (isAwarenessMessage) 15 else 50
            signals.add(
                DetectionSignal(
                    title = "طلب مشبوه لرموز سرية أو OTP",
                    description = "الرسالة تطلب أو تشير لمشاركة كود تأكيد سري أو بيانات حساسة، وهو السلوك الأبرز في سرقة المحافظ والحسابات.",
                    category = ThreatCategory.OTP_CREDENTIAL_THEFT,
                    severityPoints = points
                )
            )
            score += points
        }

        return TextAnalysisResult(
            signals = signals,
            riskScore = score.coerceIn(0, 100),
            matchedKeywords = matched,
            isOtpOrCredentialThreat = hasOtp,
            isAccountSuspensionThreat = hasSuspension
        )
    }
}
