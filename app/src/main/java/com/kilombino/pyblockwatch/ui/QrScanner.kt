package com.kilombino.pyblockwatch.ui

import android.util.Size
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors

/**
 * A full-screen QR scanner. Reads an extended public key off another screen or a paper
 * backup so the user doesn't have to type it. CameraX drives the preview; ZXing (pure
 * Java) decodes the frames. Nothing is stored — the decoded text is handed straight back.
 *
 * An xpub QR is a *dense* one (BIP-32 extended keys are ~110 base58 chars, so a version
 * 8–11 symbol with tiny modules). Two things make those readable that a naive scanner
 * gets wrong: capturing at a high enough resolution that each module survives, and letting
 * ZXing spend real effort per frame. We ask CameraX for ~1280×720 and turn on TRY_HARDER.
 */
@Composable
fun QrScannerDialog(onResult: (String) -> Unit, onDismiss: () -> Unit) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val context = LocalContext.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    DisposableEffect(Unit) { onDispose { executor.shutdown() } }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    val previewView = PreviewView(ctx)
                    val providerFuture = ProcessCameraProvider.getInstance(ctx)
                    providerFuture.addListener({
                        val provider = providerFuture.get()
                        val preview = Preview.Builder().build().also {
                            it.setSurfaceProvider(previewView.surfaceProvider)
                        }
                        // A dense xpub QR needs enough pixels that its small modules survive.
                        // The default analysis resolution (~640×480) blurs them together; ask
                        // for 1280×720 or the nearest the camera supports.
                        val resolution = ResolutionSelector.Builder()
                            .setResolutionStrategy(
                                ResolutionStrategy(
                                    Size(1280, 720),
                                    ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                                )
                            )
                            .build()
                        val analysis = ImageAnalysis.Builder()
                            .setResolutionSelector(resolution)
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        analysis.setAnalyzer(executor, QrAnalyzer { text ->
                            provider.unbindAll()
                            onResult(text)
                        })
                        provider.unbindAll()
                        runCatching {
                            provider.bindToLifecycle(
                                lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis,
                            )
                        }
                    }, ContextCompat.getMainExecutor(ctx))
                    previewView
                },
            )
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.TopStart).padding(16.dp)) {
                Text("close", color = Color.White)
            }
            Text(
                "Point the camera at a QR",
                color = Color.White,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.align(Alignment.BottomCenter).padding(40.dp),
            )
        }
    }
}

/** Decodes one QR per frame. Robust to the rotation CameraX delivers (portrait phone,
 *  landscape sensor buffer) by rotating the luminance itself — PlanarYUVLuminanceSource
 *  cannot rotate, so relying on its rotateCounterClockwise() throws and no frame ever decodes. */
private class QrAnalyzer(private val onFound: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val hints = mapOf(
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
    )
    @Volatile private var done = false

    override fun analyze(image: ImageProxy) {
        if (done) { image.close(); return }
        try {
            val w = image.width; val h = image.height
            val plane = image.planes[0]
            val rowStride = plane.rowStride
            val pixelStride = plane.pixelStride
            val buf = plane.buffer
            // Tightly pack the Y (luminance) plane into a w*h array, dropping any row padding.
            val luma = ByteArray(w * h)
            val rowBuf = ByteArray(rowStride)
            var pos = 0
            for (y in 0 until h) {
                buf.position(y * rowStride)
                val len = minOf(rowStride, buf.remaining())
                buf.get(rowBuf, 0, len)
                var x = 0; var i = 0
                while (x < w) { luma[pos++] = rowBuf[i]; i += pixelStride; x++ }
            }

            // Try every 90° orientation: the QR can be at any angle to the sensor buffer.
            var curr = luma; var cw = w; var ch = h
            var text: String? = null
            for (r in 0 until 4) {
                text = decode(curr, cw, ch)
                if (text != null) break
                val rotated = rotate90(curr, cw, ch)
                curr = rotated; val t = cw; cw = ch; ch = t
            }
            if (text != null) { done = true; onFound(text) }
        } catch (_: Exception) {
            // no QR in this frame — keep looking
        } finally {
            image.close()
        }
    }

    /** Rotate a packed luminance buffer 90° clockwise: (w×h) → (h×w). */
    private fun rotate90(src: ByteArray, w: Int, h: Int): ByteArray {
        val out = ByteArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            out[x * h + (h - 1 - y)] = src[y * w + x]
        }
        return out
    }

    /** Decode a packed luminance buffer, trying both binarizers. */
    private fun decode(luma: ByteArray, w: Int, h: Int): String? {
        val source = PlanarYUVLuminanceSource(luma, w, h, 0, 0, w, h, false)
        for (binarizer in listOf(HybridBinarizer(source), com.google.zxing.common.GlobalHistogramBinarizer(source))) {
            try {
                return MultiFormatReader().apply { setHints(hints) }
                    .decodeWithState(BinaryBitmap(binarizer)).text
            } catch (_: Exception) { /* try the next binarizer / orientation */ }
        }
        return null
    }
}
