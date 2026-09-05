package com.kilombino.pyblockwatch.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val Ink = Color(0xFF000000)
val PanelBg = Color(0xFF0A0510)
val PanelSoft = Color(0xFF0D0716)
val Line = Color(0x2EB96BFF)
val TextMain = Color(0xFFDCD0EC)
val TextSoft = Color(0xFFA99CC4)
val TextFaint = Color(0xFF6C5C86)
val Purple = Color(0xFFB96BFF)
val Orange = Color(0xFFF7931A)
val Good = Color(0xFF34D399)
val Warn = Color(0xFFFFC53D)
val Bad = Color(0xFFFF5D5D)

/** Monospace throughout: this app shows hashes, paths and addresses. */
private val mono = FontFamily.Monospace

private val typo = Typography(
    displayLarge = TextStyle(fontFamily = mono, fontSize = 44.sp, fontWeight = FontWeight.Bold),
    titleLarge = TextStyle(fontFamily = mono, fontSize = 18.sp, fontWeight = FontWeight.Bold),
    titleMedium = TextStyle(fontFamily = mono, fontSize = 14.sp, fontWeight = FontWeight.Bold),
    bodyLarge = TextStyle(fontFamily = mono, fontSize = 14.sp),
    bodyMedium = TextStyle(fontFamily = mono, fontSize = 13.sp),
    bodySmall = TextStyle(fontFamily = mono, fontSize = 11.sp),
    labelSmall = TextStyle(fontFamily = mono, fontSize = 10.sp, letterSpacing = 1.5.sp),
)

@Composable
fun PyBlockWatchTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Purple, background = Ink, surface = PanelBg,
            onPrimary = Ink, onBackground = TextMain, onSurface = TextMain,
            error = Bad,
        ),
        typography = typo,
        content = content,
    )
}
