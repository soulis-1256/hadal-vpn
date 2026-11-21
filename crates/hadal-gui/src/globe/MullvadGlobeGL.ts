/**
 * WebGL2 3D Earth mesh renderer adapted from the Mullvad VPN desktop application.
 *
 * Original work: Copyright (C) Mullvad VPN AB (<https://github.com/mullvad/mullvadvpn-app>)
 * Binary geo meshes (`public/geo/*.gl`): built with Mullvad's `globe-mesh-builder`
 * (<https://github.com/mullvad/globe-mesh-builder>) from Natural Earth vector data (CC0).
 *
 * Adapted for Hadal VPN (TypeScript / WebGL2 renderer), 2026-11-18.
 * Licensed under GNU General Public License v3.0 or later (`GPL-3.0-or-later`).
 * Provided WITHOUT ANY WARRANTY. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
 */
import { mat4Scale, type Mat4, type Vec3 } from "./globeMath";

const GEO_FILES = [
  "land_positions.gl",
  "land_triangle_indices.gl",
  "land_contour_indices.gl",
  "ocean_positions.gl",
  "ocean_indices.gl",
] as const;

const VS_SRC = `#version 300 es
in vec3 aPos;
uniform mat4 uProj;
uniform mat4 uView;
out vec3 vViewPos;
void main() {
  vec4 vp = uView * vec4(aPos, 1.0);
  vViewPos = vp.xyz;
  gl_Position = uProj * vp;
}`;

const FS_SRC = `#version 300 es
precision highp float;
in vec3 vViewPos;
uniform vec4 uColor;
uniform vec3 uCamCenter;
uniform float uIsShade;
out vec4 fragColor;
void main() {
  if (uIsShade > 0.5) {
    vec3 n = normalize(vViewPos - uCamCenter);
    vec3 ldir = normalize(vec3(-0.38, 0.48, 0.78));
    float diff = 0.78 + 0.30 * max(dot(n, ldir), 0.0);
    float rim = pow(1.0 - max(dot(n, normalize(-vViewPos)), 0.0), 2.8);
    vec3 col = uColor.rgb * diff + vec3(0.14, 0.25, 0.52) * rim * 0.45;
    fragColor = vec4(col, uColor.a);
  } else {
    fragColor = uColor;
  }
}`;

interface IndexMesh {
  ibo: WebGLBuffer;
  len: number;
}

export class MullvadGlobeGL {
  private readonly canvas: HTMLCanvasElement;
  private readonly gl: WebGL2RenderingContext | null = null;
  private readonly prog: WebGLProgram | null = null;
  private readonly loc: {
    aPos: number;
    uProj: WebGLUniformLocation | null;
    uView: WebGLUniformLocation | null;
    uColor: WebGLUniformLocation | null;
    uCamCenter: WebGLUniformLocation | null;
    uIsShade: WebGLUniformLocation | null;
  } | null = null;

  private landVbo: WebGLBuffer | null = null;
  private oceanVbo: WebGLBuffer | null = null;
  private landTri: IndexMesh | null = null;
  private landLine: IndexMesh | null = null;
  private oceanTri: IndexMesh | null = null;
  private ready = false;
  private disposed = false;

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas;
    let gl: WebGL2RenderingContext | null = null;
    try {
      gl = canvas.getContext("webgl2", {
        alpha: true,
        antialias: true,
        powerPreference: "high-performance",
      });
    } catch {
      gl = null;
    }
    if (!gl) return;
    this.gl = gl;

    const vs = this.compileShader(gl, gl.VERTEX_SHADER, VS_SRC);
    const fs = this.compileShader(gl, gl.FRAGMENT_SHADER, FS_SRC);
    const prog = gl.createProgram();
    if (!vs || !fs || !prog) {
      if (vs) gl.deleteShader(vs);
      if (fs) gl.deleteShader(fs);
      if (prog) gl.deleteProgram(prog);
      return;
    }
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.deleteShader(vs);
    gl.deleteShader(fs);

    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      gl.deleteProgram(prog);
      return;
    }

    this.prog = prog;
    this.loc = {
      aPos: gl.getAttribLocation(prog, "aPos"),
      uProj: gl.getUniformLocation(prog, "uProj"),
      uView: gl.getUniformLocation(prog, "uView"),
      uColor: gl.getUniformLocation(prog, "uColor"),
      uCamCenter: gl.getUniformLocation(prog, "uCamCenter"),
      uIsShade: gl.getUniformLocation(prog, "uIsShade"),
    };

    void this.loadGeo();
  }

  private compileShader(
    gl: WebGL2RenderingContext,
    type: number,
    src: string,
  ): WebGLShader | null {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, src);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader);
      return null;
    }
    return shader;
  }

  private async loadGeo(): Promise<void> {
    if (!this.gl || typeof fetch !== "function") return;
    try {
      const buffers = await Promise.all(
        GEO_FILES.map(async (file) => {
          const res = await fetch(`./geo/${file}`);
          if (!res.ok) throw new Error(`HTTP ${res.status} loading ${file}`);
          return res.arrayBuffer();
        }),
      );
      if (this.disposed || !this.gl) return;

      const [lp, lt, lc, op, oi] = buffers;
      const gl = this.gl;
      const makeBuf = (target: number, data: ArrayBuffer): WebGLBuffer | null => {
        const buf = gl.createBuffer();
        if (!buf) return null;
        gl.bindBuffer(target, buf);
        gl.bufferData(target, data, gl.STATIC_DRAW);
        return buf;
      };

      const landVbo = makeBuf(gl.ARRAY_BUFFER, lp);
      const oceanVbo = makeBuf(gl.ARRAY_BUFFER, op);
      const landTriIbo = makeBuf(gl.ELEMENT_ARRAY_BUFFER, lt);
      const landLineIbo = makeBuf(gl.ELEMENT_ARRAY_BUFFER, lc);
      const oceanTriIbo = makeBuf(gl.ELEMENT_ARRAY_BUFFER, oi);
      if (!landVbo || !oceanVbo || !landTriIbo || !landLineIbo || !oceanTriIbo) return;

      this.landVbo = landVbo;
      this.oceanVbo = oceanVbo;
      this.landTri = { ibo: landTriIbo, len: lt.byteLength / 4 };
      this.landLine = { ibo: landLineIbo, len: lc.byteLength / 4 };
      this.oceanTri = { ibo: oceanTriIbo, len: oi.byteLength / 4 };
      this.ready = true;
    } catch {
      // Fallback gradient sphere in OrbitGlobe stays visible while/if geo is unavailable.
    }
  }

  draw(proj: Mat4, view: Mat4, centerView: Vec3, isProtected: boolean): boolean {
    const gl = this.gl;
    if (
      !gl ||
      !this.ready ||
      !this.prog ||
      !this.loc ||
      !this.landVbo ||
      !this.oceanVbo ||
      !this.landTri ||
      !this.landLine ||
      !this.oceanTri
    ) {
      return false;
    }

    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.clearColor(0, 0, 0, 0);
    gl.clearDepth(1.0);
    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    gl.useProgram(this.prog);
    gl.uniformMatrix4fv(this.loc.uProj, false, proj);
    gl.uniform3fv(this.loc.uCamCenter, centerView);

    const drawEl = (
      vbo: WebGLBuffer,
      ibo: WebGLBuffer,
      len: number,
      mat: Mat4,
      col: [number, number, number, number],
      mode: number,
      shade: boolean,
    ) => {
      gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
      gl.vertexAttribPointer(this.loc!.aPos, 3, gl.FLOAT, false, 0, 0);
      gl.enableVertexAttribArray(this.loc!.aPos);
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, ibo);
      gl.uniformMatrix4fv(this.loc!.uView, false, mat);
      gl.uniform4fv(this.loc!.uColor, col);
      gl.uniform1f(this.loc!.uIsShade, shade ? 1 : 0);
      gl.drawElements(mode, len, gl.UNSIGNED_INT, 0);
    };

    const landCol: [number, number, number, number] = isProtected
      ? [0.095, 0.2, 0.34, 1]
      : [0.105, 0.175, 0.365, 1];
    const oceanCol: [number, number, number, number] = [0.032, 0.062, 0.145, 1];
    const contourCol: [number, number, number, number] = [0.042, 0.082, 0.185, 1];

    drawEl(this.landVbo, this.landLine.ibo, this.landLine.len, view, contourCol, gl.LINE_STRIP, false);
    const landView = mat4Scale(view, 0.9997);
    drawEl(this.landVbo, this.landTri.ibo, this.landTri.len, landView, landCol, gl.TRIANGLES, true);
    drawEl(this.oceanVbo, this.oceanTri.ibo, this.oceanTri.len, view, oceanCol, gl.TRIANGLES, true);
    return true;
  }

  dispose(): void {
    this.disposed = true;
    const gl = this.gl;
    if (!gl) return;
    if (this.landVbo) gl.deleteBuffer(this.landVbo);
    if (this.oceanVbo) gl.deleteBuffer(this.oceanVbo);
    if (this.landTri) gl.deleteBuffer(this.landTri.ibo);
    if (this.landLine) gl.deleteBuffer(this.landLine.ibo);
    if (this.oceanTri) gl.deleteBuffer(this.oceanTri.ibo);
    if (this.prog) gl.deleteProgram(this.prog);
    this.ready = false;
  }
}
