"""Build the optional narrated video on Windows with Pillow, ffmpeg, and SAPI."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SCENES = [
    ("SECURITY RAG", "One synthetic investigation", [
        "git clone github.com/Josh-Shultis/security-rag-demo",
        "python -m pip install -e .",
        "python -m security_rag.investigation",
    ], "Offline. Temporary index. No real evidence."),
    ("THE QUESTION", "Can Account A read Account B's owner-only note?", [
        "Requester: Account A",
        "Owner: Account B",
        "Attacker input: SYNTH-NOTE-B-1",
        "Variable: ownership check in the read method",
    ], "Both accounts are simulated strings in a mock."),
    ("DECISIVE FIXTURE", "The vulnerable method returns the canary", [
        "GET-style read by Account A -> status 200",
        "Owner in response: Account B",
        "Returned text: SYNTH-CANARY-B-7",
        "Fixture regenerated and compared before indexing",
    ], "A synthetic response is not a real network capture."),
    ("TRACE TO SOURCE", "Conclusion -> hit -> artifact -> supplied bytes", [
        "03_vulnerable_response.json",
        "SHA-256: e01139e29eb68d0c...ac9667afc",
        "art-SYNTH-001-e01139e29eb68d0c",
        "chk-SYNTH-001-e01139e29eb6-0001-0001",
    ], "The runner checks the full hash, not just this display."),
    ("CONTROLS", "The fix blocks this exact read", [
        "Account A -> fixed method -> 403",
        "Account B -> fixed method -> 200",
        "Unknown note -> vulnerable method -> 404",
    ], "404 is a negative control, not proof of authorization."),
    ("RESEARCH JUDGMENT", "What the demo supports, and what it cannot", [
        "Supports: a deliberate mock bug and regression check",
        "Does not prove: a real product vulnerability or ACL",
        "Tests: offline run, fixture match, source hash, controls",
        "Authorship: Codex-assisted public release, disclosed",
    ], "Private captures stay outside Git. Review the case study."),
]


def font(size: int, mono: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    name = "consola.ttf" if mono else "segoeui.ttf"
    windows = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / name
    try:
        return ImageFont.truetype(str(windows), size)
    except OSError:
        return ImageFont.load_default(size=size)


def make_slide(number: int, target: Path) -> None:
    title, subtitle, lines, footer = SCENES[number - 1]
    image = Image.new("RGB", (1280, 720), "#0B1220")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((42, 42, 1238, 678), radius=28, fill="#111D30", outline="#29415A", width=2)
    draw.rounded_rectangle((72, 74, 318, 112), radius=14, fill="#127D73")
    draw.text((92, 81), "SYNTHETIC CASE  /  0" + str(number), font=font(20, True), fill="#E9FFFA")
    draw.text((78, 146), title, font=font(55), fill="#F4F8FC")
    draw.text((80, 225), subtitle, font=font(29), fill="#8DD9CD")
    draw.line((80, 289, 1200, 289), fill="#36536D", width=2)
    y = 328
    for line in lines:
        draw.rounded_rectangle((80, y - 4, 1198, y + 56), radius=12, fill="#192A3F")
        draw.text((104, y + 10), line, font=font(25, True), fill="#E7EEF5")
        y += 72
    draw.text((80, 630), footer, font=font(20), fill="#A9B9CB")
    image.save(target)


def call(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def duration(path: Path) -> float:
    raw = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)], text=True)
    return float(json.loads(raw)["format"]["duration"])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="security-rag-video-") as scratch:
        work = Path(scratch)
        audio = work / "audio"
        audio.mkdir()
        call("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "tools" / "narrate_walkthrough.ps1"), "-OutputDirectory", str(audio))
        playlist = work / "segments.txt"
        entries = []
        for number in range(1, 7):
            still = work / f"scene-{number:02}.png"
            wave = audio / f"scene-{number:02}.wav"
            segment = work / f"scene-{number:02}.mp4"
            make_slide(number, still)
            length = duration(wave) + 2
            call("ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-framerate", "24", "-i", str(still), "-i", str(wave), "-af", "apad=pad_dur=2", "-t", f"{length:.3f}", "-c:v", "libx264", "-preset", "fast", "-tune", "stillimage", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", str(segment))
            entries.append(f"file '{segment.as_posix()}'")
        playlist.write_text("\n".join(entries) + "\n", encoding="utf-8")
        destination = ROOT / "media" / "walkthrough.mp4"
        call("ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(playlist), "-c", "copy", str(destination))
        print(f"{destination}: {duration(destination):.1f} seconds")


if __name__ == "__main__":
    main()
