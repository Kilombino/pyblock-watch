package com.kilombino.pyblockwatch.ui

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
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
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors

/**
 * A full-screen QR scanner. Reads an extended public key off another screen or a paper
 * backup so the user doesn't have to type it. CameraX drives the preview; ZXing (pure
 * Java) decodes the frames. Nothing is stored — the decoded text is handed straight back.
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
                        val analysis = ImageAnalysis.Builder()
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
                Text("cerrar", color = Color.White)
            }
            Text(
                "Apunta al QR de tu xpub",
                color = Color.White,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.align(Alignment.BottomCenter).padding(40.dp),
            )
        }
    }
}

/** Decodes one QR per frame from the Y (luminance) plane; fires [onFound] once. */
private class QrAnalyzer(private val onFound: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = QRCodeReader()
    @Volatile private var done = false

    override fun analyze(image: ImageProxy) {
        if (done) { image.close(); return }
        try {
            val plane = image.planes[0]
            val buffer = plane.buffer
            val data = ByteArray(buffer.remaining()); buffer.get(data)
            val rowStride = plane.rowStride
            val source = PlanarYUVLuminanceSource(
                data, rowStride, image.height, 0, 0, image.width, image.height, false,
            )
            val result = reader.decode(BinaryBitmap(HybridBinarizer(source)))
            done = true
            onFound(result.text)
        } catch (_: Exception) {
            // no QR in this frame — keep looking
        } finally {
            reader.reset()
            image.close()
        }
    }
}
