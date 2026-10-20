# كاشف (Kashef) | درع الحماية من الاحتيال والنصب الإلكتروني

تطبيق أندرويد مفتوح وسريع مبني بأحدث معايير **Jetpack Compose** و **Material 3**، مصمم خصيصاً لحماية المستخدمين في مصر والوطن العربي من محاولات النصب المتكررة (سرقة حسابات إنستاباي، اختراق المحافظ الإلكترونية، التصيد باسم البنوك، رسائل البريد المصري المزيفة، وفخاخ التوظيف الوهمي على تليجرام).

---

## 🌟 المزايا الجوهرية (Core Features)

1. **فحص محلي فوري وآمن 100% (On-Device Zero Knowledge):**
   - لا يتم إرسال بيانات المستخدم أو رسائله لأي سيرفر خارجي. التحليل يتم بالكامل محلياً داخل جهاز المستخدم في أجزاء من الثانية.
2. **فحص الروابط والنطاقات (Intelligent URL Heuristics):**
   - **القائمة البيضاء الرسمية (Official Whitelist):** مطابقة النطاقات الرسمية للبنوك المصرية (الأهلي، مصر، CIB، QNB، القاهرة، إلخ)، شبكة إنستاباي (`instapay.eg`)، فودافون كاش، أورنج، إي آند، وي، والبريد المصري.
   - **كشف انتحال الهوية (Brand Impersonation & Typosquatting):** رصد أي محاولة لاستخدام اسم مؤسسة رسمية داخل دومين مشبوه أو نطاق فرعي مضلل.
   - **رصد النطاقات الرخيصة المشبوهة (High-Risk TLDs):** فحص النطاقات سريعة الإنشاء (`.xyz`, `.top`, `.site`, `.fun`, `.club`, `.space`).
   - **كشف اختصار الروابط:** التنبيه عند استخدام خدمات إخفاء الروابط (`bit.ly`, `tinyurl`, إلخ).
3. **تحليل نصوص الهندسة الاجتماعية (Social Engineering Heuristics):**
   - كشف رسائل الترهيب البنكي ("تم إيقاف حسابك"، "تحديث بيانات الفيزا").
   - كشف طلبات الرموز السرية وسرقة الـ OTP.
   - كشف احتيال وظائف تليجرام ولايكات يوتيوب.
   - كشف احتيال طرود وشحنات البريد المصري.
4. **التكامل المباشر مع النظام (Android System Integration):**
   - يدعم **ACTION_SEND**: المستخدم يقدر يعمل "Share" لأي رسالة من واتساب أو الرسائل القصيرة لتطبيق كاشف ليفحصها مباشرة.
   - ميزة "لصق وفحص" بضغطة زر واحدة.
5. **محرك الانتشار الفيروسي (Viral Warning Card):**
   - زر مدمج لتوليد رسالة تحذيرية منسقة وجاهزة للمشاركة على واتساب وفيسبوك لتحذير العائلة والأصدقاء من الرابط المفحوص، مما يدفع المستخدمين الجدد لتحميل التطبيق بشكل عضوي.

---

## 🏗️ الهيكلية التقنية (Architecture)

* **UI Layer:** Jetpack Compose + Material 3 + Animations.
* **Architecture:** Clean Architecture + MVVM + StateFlow + Kotlin Coroutines.
* **Data Layer:** Room Database لحفظ سجل الفحوصات محلياً.
* **Compatibility:** Android 7.0 (API 24) فما فوق، مع جاهزية كاملة لـ Android 15 (API 35).

---

## 📁 هيكل المشروع (Project Layout)

```
kashef-scam-shield/
├── app/
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   └── java/eg/kashef/shield/
│   │       ├── MainActivity.kt
│   │       ├── core/
│   │       │   ├── analyzer/
│   │       │   │   ├── UrlAnalyzer.kt
│   │       │   │   └── TextMessageHeuristicAnalyzer.kt
│   │       │   ├── engine/
│   │       │   │   └── ScamShieldEngine.kt
│   │       │   └── whitelist/
│   │       │       └── EgyptianEntitiesWhitelist.kt
│   │       ├── data/local/
│   │       │   └── ScanHistoryDatabase.kt
│   │       ├── domain/model/
│   │       │   └── Models.kt
│   │       └── ui/
│   │           ├── HomeScreen.kt
│   │           └── MainViewModel.kt
│   └── build.gradle.kts
└── settings.gradle.kts
```

---

## 🚀 التشغيل والتطوير (How to Run)

1. افتح المشروع في **Android Studio** أو محرر **Antigravity**.
2. اسمح لـ Gradle بمزامنة المكتبات (Sync Project with Gradle Files).
3. شغّل التطبيق على محاكي (Emulator) أو هاتف حقيقي عبر `Run 'app'`.
4. لتشغيل الاختبارات:
   ```bash
   ./gradlew test
   ```
