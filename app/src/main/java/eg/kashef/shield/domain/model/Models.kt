package eg.kashef.shield.domain.model

enum class RiskLevel(val arabicTitle: String, val colorHex: String) {
    SAFE("آمن وموثوق", "#10B981"),
    SUSPICIOUS("مشبوه - توخّ الحذر", "#F59E0B"),
    DANGEROUS("خطر - احتيال مؤكد", "#EF4444")
}

enum class ThreatCategory(val arabicLabel: String) {
    OFFICIAL_VERIFIED("مؤسسة رسمية معتمدة"),
    BRAND_IMPERSONATION("انتحال صفة بنك أو خدمة رسمية"),
    TYPOSQUATTING_DOMAIN("تلاعب في حروف اسم الموقع"),
    HIGH_RISK_TLD("نطاق إنترنت رخيص ومشبوه"),
    DIRECT_IP_ADDRESS("رابط مباشر لعنوان IP مجهول"),
    SUSPICIOUS_SHORTENER("اختصار روابط لإخفاء الوجهة الحقيقية"),
    ACCOUNT_SUSPENSION_PHISHING("تصيد عبر التهديد بإيقاف الحساب"),
    OTP_CREDENTIAL_THEFT("محاولة سرقة رمز التحقق (OTP) أو الفيزا"),
    FAKE_POSTAL_DELIVERY("احتيال باسم البريد المصري وشحنات وهمية"),
    TELEGRAM_TASK_SCAM("احتيال التوظيف الوهمي ومهام تليجرام"),
    FAKE_PRIZE_LOTTERY("مسابقات وجوائز نقدية وهمية"),
    NONE("لا توجد مؤشرات خطر")
}

data class DetectionSignal(
    val title: String,
    val description: String,
    val category: ThreatCategory,
    val severityPoints: Int
)

data class AnalysisResult(
    val riskLevel: RiskLevel,
    val score: Int, // 0 to 100
    val extractedUrl: String?,
    val extractedDomain: String?,
    val isOfficialDomain: Boolean,
    val officialEntityName: String?,
    val headline: String,
    val detailedSummary: String,
    val signals: List<DetectionSignal>,
    val actionAdvice: List<String>,
    val shareableWarningText: String
)
