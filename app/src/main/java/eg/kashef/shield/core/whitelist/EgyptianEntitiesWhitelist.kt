package eg.kashef.shield.core.whitelist

data class OfficialEntity(
    val id: String,
    val nameArabic: String,
    val primaryDomain: String,
    val allowedSubdomains: List<String> = emptyList(),
    val knownBrandKeywords: List<String> = emptyList()
)

object EgyptianEntitiesWhitelist {

    val OFFICIAL_ENTITIES: List<OfficialEntity> = listOf(
        // Banks
        OfficialEntity(
            id = "nbe",
            nameArabic = "البنك الأهلي المصري (NBE)",
            primaryDomain = "nbe.com.eg",
            knownBrandKeywords = listOf("nbe", "alahli", "ahli", "البنك الاهلي", "البنك الأهلي")
        ),
        OfficialEntity(
            id = "bm",
            nameArabic = "بنك مصر (Banque Misr)",
            primaryDomain = "banquemisr.com",
            allowedSubdomains = listOf("bm.com.eg"),
            knownBrandKeywords = listOf("banquemisr", "بنك مصر", "misr bank")
        ),
        OfficialEntity(
            id = "cib",
            nameArabic = "البنك التجاري الدولي (CIB)",
            primaryDomain = "cibeg.com",
            knownBrandKeywords = listOf("cib", "cibeg", "البنك التجاري الدولي")
        ),
        OfficialEntity(
            id = "qnb",
            nameArabic = "بنك قطر الوطني (QNB Alahli)",
            primaryDomain = "qnb.com.eg",
            knownBrandKeywords = listOf("qnb", "qnb alahli")
        ),
        OfficialEntity(
            id = "alexbank",
            nameArabic = "بنك الإسكندرية (AlexBank)",
            primaryDomain = "alexbank.com",
            knownBrandKeywords = listOf("alexbank", "بنك الاسكندرية", "بنك الإسكندرية")
        ),
        OfficialEntity(
            id = "bdc",
            nameArabic = "بنك القاهرة (Banque du Caire)",
            primaryDomain = "bdc.com.eg",
            knownBrandKeywords = listOf("bdc", "بنك القاهرة")
        ),
        OfficialEntity(
            id = "aaib",
            nameArabic = "البنك العربي الأفريقي الدولي (AAIB)",
            primaryDomain = "aaib.com",
            knownBrandKeywords = listOf("aaib", "البنك العربي الافريقي")
        ),
        OfficialEntity(
            id = "faisal",
            nameArabic = "بنك فيصل الإسلامي المصري",
            primaryDomain = "faisalbank.com.eg",
            knownBrandKeywords = listOf("faisal", "بنك فيصل")
        ),
        OfficialEntity(
            id = "adib",
            nameArabic = "مصرف أبوظبي الإسلامي - مصر",
            primaryDomain = "adib.eg",
            knownBrandKeywords = listOf("adib", "ابوظبي الاسلامي")
        ),

        // Wallets & National Payment Schemes
        OfficialEntity(
            id = "instapay",
            nameArabic = "شبكة المدفوعات اللحظية (إنستاباي - InstaPay)",
            primaryDomain = "instapay.eg",
            knownBrandKeywords = listOf("instapay", "انستاباي", "انستا باي", "insta-pay")
        ),
        OfficialEntity(
            id = "fawry",
            nameArabic = "شبكة فوري للمدفوعات",
            primaryDomain = "fawry.com",
            knownBrandKeywords = listOf("fawry", "فوري")
        ),
        OfficialEntity(
            id = "meeza",
            nameArabic = "بطاقات الدفع الوطنية ميزة",
            primaryDomain = "meeza.com.eg",
            knownBrandKeywords = listOf("meeza", "ميزة")
        ),
        OfficialEntity(
            id = "vodafone",
            nameArabic = "فودافون مصر / فودافون كاش",
            primaryDomain = "vodafone.com.eg",
            knownBrandKeywords = listOf("vodafone", "فودافون", "فودافون كاش", "vf cash")
        ),
        OfficialEntity(
            id = "orange",
            nameArabic = "أورنج مصر / أورنج كاش",
            primaryDomain = "orange.eg",
            knownBrandKeywords = listOf("orange", "اورنج", "أورنج", "اورنج كاش")
        ),
        OfficialEntity(
            id = "etisalat",
            nameArabic = "إي آند مصر (اتصالات سابقاً) / اتصالات كاش",
            primaryDomain = "etisalat.eg",
            allowedSubdomains = listOf("eand.com.eg"),
            knownBrandKeywords = listOf("etisalat", "اتصالات", "اتصالات كاش", "e&")
        ),
        OfficialEntity(
            id = "we",
            nameArabic = "المصرية للاتصالات (WE) / وي باي",
            primaryDomain = "te.eg",
            allowedSubdomains = listOf("we.com.eg"),
            knownBrandKeywords = listOf("we.com", "المصرية للاتصالات", "we pay")
        ),

        // Government & Postal
        OfficialEntity(
            id = "egyptpost",
            nameArabic = "الهيئة القومية للبريد المصري",
            primaryDomain = "egyptpost.org",
            knownBrandKeywords = listOf("egyptpost", "البريد المصري", "بريد مصر", "egypt post")
        ),
        OfficialEntity(
            id = "digital_egypt",
            nameArabic = "بوابة مصر الرقمية الحكومية",
            primaryDomain = "digital.gov.eg",
            allowedSubdomains = listOf("egypt.gov.eg"),
            knownBrandKeywords = listOf("مصر الرقمية", "digital egypt")
        ),
        OfficialEntity(
            id = "cbe",
            nameArabic = "البنك المركزي المصري (CBE)",
            primaryDomain = "cbe.org.eg",
            knownBrandKeywords = listOf("البنك المركزي", "central bank of egypt", "cbe")
        )
    )

    private val domainToEntityMap: Map<String, OfficialEntity> by lazy {
        val map = mutableMapOf<String, OfficialEntity>()
        for (entity in OFFICIAL_ENTITIES) {
            map[entity.primaryDomain.lowercase()] = entity
            for (sub in entity.allowedSubdomains) {
                map[sub.lowercase()] = entity
            }
        }
        map
    }

    fun findOfficialEntityByDomain(rootDomain: String): OfficialEntity? {
        val normalized = rootDomain.lowercase().trim()
        return domainToEntityMap[normalized]
    }

    fun findBrandImpersonated(targetString: String): OfficialEntity? {
        val lower = targetString.lowercase()
        return OFFICIAL_ENTITIES.firstOrNull { entity ->
            entity.knownBrandKeywords.any { kw -> lower.contains(kw.lowercase()) }
        }
    }
}
