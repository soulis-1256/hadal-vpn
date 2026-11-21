export const GLOBE_W = 360;
export const GLOBE_H = 540;
export const GLOBE_FOV_RAD = (46 * Math.PI) / 180;
export const GLOBE_POSE_CY = 218;
export const GLOBE_FOCUS_CY = 230;
export const GLOBE_MIN_ZOOM = 0.8;
export const GLOBE_MAX_ZOOM = 7.5;
export const GLOBE_FOCUS_ZOOM = 3.8;
export const GLOBE_MAX_LAT = 72;

const DEG_TO_RAD = Math.PI / 180;

export type Mat4 = Float32Array;
export type Vec3 = [number, number, number];
export type Vec4 = [number, number, number, number];

export interface CameraTransform {
  camDist: number;
  cx: number;
  cy: number;
  ty: number;
  appR: number;
  view: Mat4;
  proj: Mat4;
  mvp: Mat4;
  centerView: Vec3;
}

export interface ProjectedPoint {
  x: number;
  y: number;
  visible: boolean;
  viewZ: number;
  /** Cosine of surface-normal angle toward camera in [0, 1]; fades smoothly near the horizon limb. */
  facing: number;
}

/** Normalize longitude cleanly into [-180, 180). */
export function wrapLon(lon: number): number {
  return (((lon + 540) % 360) + 360) % 360 - 180;
}

/** Clamp latitude inside navigable polar bounds [-72, 72]. */
export function clampLat(lat: number): number {
  return Math.max(-GLOBE_MAX_LAT, Math.min(GLOBE_MAX_LAT, lat));
}

/** Convert geographic (lat, lon) in degrees to unit-sphere cartesian vector (Y-up, Z-prime-meridian). */
export function latLonToVec(lat: number, lon: number): Vec3 {
  const latR = lat * DEG_TO_RAD;
  const lonR = lon * DEG_TO_RAD;
  const cosLat = Math.cos(latR);
  return [cosLat * Math.sin(lonR), Math.sin(latR), cosLat * Math.cos(lonR)];
}

export function mat4Identity(): Mat4 {
  return new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);
}

export function mat4Perspective(fovy: number, aspect: number, near: number, far: number): Mat4 {
  const f = 1 / Math.tan(fovy / 2);
  const nf = 1 / (near - far);
  return new Float32Array([
    f / aspect,
    0,
    0,
    0,
    0,
    f,
    0,
    0,
    0,
    0,
    (far + near) * nf,
    -1,
    0,
    0,
    2 * far * near * nf,
    0,
  ]);
}

export function mat4Mul(a: Mat4, b: Mat4): Mat4 {
  const out = new Float32Array(16);
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      out[c * 4 + r] =
        a[r] * b[c * 4] +
        a[4 + r] * b[c * 4 + 1] +
        a[8 + r] * b[c * 4 + 2] +
        a[12 + r] * b[c * 4 + 3];
    }
  }
  return out;
}

export function mat4Translate(m: Mat4, x: number, y: number, z: number): Mat4 {
  return mat4Mul(m, new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, x, y, z, 1]));
}

export function mat4RotateX(m: Mat4, angleRad: number): Mat4 {
  const c = Math.cos(angleRad);
  const s = Math.sin(angleRad);
  return mat4Mul(m, new Float32Array([1, 0, 0, 0, 0, c, s, 0, 0, -s, c, 0, 0, 0, 0, 1]));
}

export function mat4RotateY(m: Mat4, angleRad: number): Mat4 {
  const c = Math.cos(angleRad);
  const s = Math.sin(angleRad);
  return mat4Mul(m, new Float32Array([c, 0, -s, 0, 0, 1, 0, 0, s, 0, c, 0, 0, 0, 0, 1]));
}

export function mat4Scale(m: Mat4, s: number): Mat4 {
  return mat4Mul(m, new Float32Array([s, 0, 0, 0, 0, s, 0, 0, 0, 0, s, 0, 0, 0, 0, 1]));
}

export function transformVec4(m: Mat4, x: number, y: number, z: number): Vec4 {
  return [
    m[0] * x + m[4] * y + m[8] * z + m[12],
    m[1] * x + m[5] * y + m[9] * z + m[13],
    m[2] * x + m[6] * y + m[10] * z + m[14],
    m[3] * x + m[7] * y + m[11] * z + m[15],
  ];
}

/**
 * Compute camera view/projection matrices with front-surface focus compensation.
 *
 * At overview zoom (1.0), sphere center rests at baseCy (218px). As zoom increases,
 * depth reference shifts to the front sphere surface (camDist - 1) and screen center
 * shifts toward cyFocus (230px) so clicked pins project onto dead-center viewport coordinates.
 */
export function computeCameraTransform(
  lat0: number,
  lon0: number,
  zoom: number,
  baseCy = GLOBE_POSE_CY,
): CameraTransform {
  const aspect = GLOBE_W / GLOBE_H;
  const tanHalf = Math.tan(GLOBE_FOV_RAD / 2);
  const camDist = 1.0 + 3.36 / zoom;
  const cx = GLOBE_W / 2;
  const surfBlend = Math.min(1, Math.max(0, (zoom - 1) / 1.2));
  const cyFocus = baseCy + (GLOBE_FOCUS_CY - baseCy) * surfBlend;
  const ndcY = (GLOBE_H / 2 - cyFocus) / (GLOBE_H / 2);
  const refZ = camDist - surfBlend;
  const ty = ndcY * refZ * tanHalf;
  const cy = GLOBE_H / 2 - (GLOBE_H / 2) * (ty / (camDist * tanHalf));

  const proj = mat4Perspective(GLOBE_FOV_RAD, aspect, 0.35, 15);
  let view = mat4Identity();
  view = mat4Translate(view, 0, ty, -camDist);
  view = mat4RotateX(view, lat0 * DEG_TO_RAD);
  view = mat4RotateY(view, -lon0 * DEG_TO_RAD);
  const mvp = mat4Mul(proj, view);
  const centerView: Vec3 = [0, ty, -camDist];
  const appR = (GLOBE_H / 2) * (1 / Math.sqrt(Math.max(0.05, camDist * camDist - 1))) / tanHalf;

  return { camDist, cx, cy, ty, appR, view, proj, mvp, centerView };
}

/** Project a geographic surface coordinate onto logical 360x540 screen space with horizon culling. */
export function projectSurfacePoint(
  lat: number,
  lon: number,
  cam: CameraTransform,
): ProjectedPoint {
  const [px, py, pz] = latLonToVec(lat, lon);
  const r = 1.002;
  const [vx, vy, vz] = transformVec4(cam.view, px * r, py * r, pz * r);
  const [cxp, cyp, _czp, cwp] = transformVec4(cam.mvp, px * r, py * r, pz * r);
  const nx = vx - cam.centerView[0];
  const ny = vy - cam.centerView[1];
  const nz = vz - cam.centerView[2];
  const dot = nx * -vx + ny * -vy + nz * -vz;
  const dist = Math.hypot(vx, vy, vz) || 1;
  const visible = dot > 0.015;
  return {
    x: ((cxp / cwp) * 0.5 + 0.5) * GLOBE_W,
    y: (0.5 - (cyp / cwp) * 0.5) * GLOBE_H,
    visible,
    viewZ: vz,
    facing: Math.max(0, Math.min(1, dot / dist)),
  };
}
