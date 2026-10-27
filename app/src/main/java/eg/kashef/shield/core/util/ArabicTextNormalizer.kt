package eg.kashef.shield.core.util

import java.util.regex.Pattern

object ArabicTextNormalizer {

    private val DIACRITICS_PATTERN = Pattern.compile("[\u064B-\u065F\u0670]")
    private val TATWEEL_PATTERN = Pattern.compile("\u0640")
    private val ZERO_WIDTH_PATTERN = Pattern.compile("[\u200B\u200C\u200D\uFEFF\u00AD]")
    private val MULTI_SPACE_PATTERN = Pattern.compile("\\s+")
    
    // Pattern to detect single Arabic letters separated by whitespace (e.g. "إ ي ق ا ف" -> "ايقاف")
    private val SPACED_LETTERS_PATTERN = Pattern.compile("(?<=\\b[\\u0600-\\u06FF])\\s+(?=[\\u0600-\\u06FF]\\b)")

    /**
     * Deep normalizer for text heuristics analysis.
     * Removes diacritics, tatweel, invisible characters, unifies letters,
     * collapses spaced-out characters, and trims whitespace.
     */
    fun normalize(text: String): String {
        if (text.isBlank()) return ""

        var s = text

        // 1. Remove invisible / zero-width characters
        s = ZERO_WIDTH_PATTERN.matcher(s).replaceAll("")

        // 2. Remove tatweel (kashida: ـ)
        s = TATWEEL_PATTERN.matcher(s).replaceAll("")

        // 3. Remove Arabic diacritics (tashkeel & tanween)
        s = DIACRITICS_PATTERN.matcher(s).replaceAll("")

        // 4. Normalize Alefs
        s = s.replace('أ', 'ا')
            .replace('إ', 'ا')
            .replace('آ', 'ا')
            .replace('ٱ', 'ا')

        // 5. Normalize Ya and Alef Maqsura
        s = s.replace('ى', 'ي')

        // 6. Normalize Ta Marbuta to Ha
        s = s.replace('ة', 'ه')

        // 7. De-space intentionally spaced letters (e.g. "ت م  ا ي ق ا ف" -> "تم ايقاف")
        var prev = ""
        while (prev != s) {
            prev = s
            s = SPACED_LETTERS_PATTERN.matcher(s).replaceAll("")
        }

        // 8. Collapse whitespace and lowercase Latin letters
        s = MULTI_SPACE_PATTERN.matcher(s).replaceAll(" ").trim().lowercase()

        return s
    }
}
