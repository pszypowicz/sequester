#!/usr/bin/env swift
import AppKit

// Renders the Sequester app icon: a white key glyph on a slate-to-blue
// rounded-square, at 1024x1024, written as PNG. build-icon.sh scales it to
// an iconset and packs the .icns.

let size = 1024.0
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

guard let ctx = NSGraphicsContext.current?.cgContext else {
    fatalError("no graphics context")
}

// Rounded-square background with a diagonal gradient.
let margin = size * 0.06
let rect = NSRect(x: margin, y: margin, width: size - 2 * margin, height: size - 2 * margin)
let radius = rect.width * 0.2237
let path = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
path.addClip()

let top = NSColor(calibratedRed: 0.16, green: 0.22, blue: 0.34, alpha: 1)
let bottom = NSColor(calibratedRed: 0.11, green: 0.35, blue: 0.72, alpha: 1)
let gradient = NSGradient(starting: top, ending: bottom)!
gradient.draw(in: path, angle: -90)

// White key glyph, centered. The SF Symbol is a template silhouette, so it
// is tinted white with a source-atop fill before compositing.
let config = NSImage.SymbolConfiguration(pointSize: size * 0.5, weight: .semibold)
if let base = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(config) {
    let s = base.size
    let tinted = NSImage(size: s)
    tinted.lockFocus()
    base.draw(in: NSRect(origin: .zero, size: s))
    NSColor.white.set()
    NSRect(origin: .zero, size: s).fill(using: .sourceAtop)
    tinted.unlockFocus()

    let origin = NSPoint(x: (size - s.width) / 2, y: (size - s.height) / 2)
    tinted.draw(in: NSRect(origin: origin, size: s), from: .zero, operation: .sourceOver, fraction: 1)
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fatalError("failed to encode PNG")
}
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon-1024.png"
try! png.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
