# Third-Party Notices

This project (`GPL-3.0-or-later`) includes third-party open-source code, binary geometry
buffers, fonts, and icon assets under the terms below.

## Mullvad VPN 3D Globe Pipeline & Binary Geometry (`GPL-3.0-or-later`)

- **WebGL2 Mesh/Shader Renderer (`src/globe/MullvadGlobeGL.ts`)**
  - Upstream source: <https://github.com/mullvad/mullvadvpn-app>
  - Copyright: Copyright (C) Mullvad VPN AB
  - License: GNU General Public License v3.0 or later (`GPL-3.0-or-later`)
  - Modification notice: Adapted for Hadal VPN's SolidJS/TypeScript WebGL2 renderer on 2026-11-18.

- **Binary 3D Globe Mesh Buffers (`crates/hadal-gui/public/geo/*.gl`)**
  - Upstream Corresponding Source generator: <https://github.com/mullvad/globe-mesh-builder>
  - Upstream application distribution: <https://github.com/mullvad/mullvadvpn-app>
  - Copyright: Copyright (C) Mullvad VPN AB
  - License: GNU General Public License v3.0 or later (`GPL-3.0-or-later`)
  - Included files in `public/geo/`:
    - `land_positions.gl` (`f32` spherical vertex positions)
    - `land_triangle_indices.gl` (`u32` landmass triangle indices)
    - `land_contour_indices.gl` (`u32` coastline line-strip indices)
    - `ocean_positions.gl` (`f32` ocean sphere vertex positions)
    - `ocean_indices.gl` (`u32` ocean sphere triangle indices)

## Natural Earth Vector Coastline & Boundary Data (`CC0` / Public Domain)

- **Natural Earth Coastline & Land Polygons**
  - Underlying cartographic vector dataset processed by `mullvad/globe-mesh-builder`
  - Source: <https://www.naturalearthdata.com/>
  - License: Public Domain (`CC0` / Natural Earth Terms of Use)

## Self-Hosted Webfonts (`OFL-1.1`)

- **`@fontsource/chakra-petch`** and **`@fontsource/ibm-plex-mono`**
  - License: SIL Open Font License 1.1 (`OFL-1.1`)

## UI Iconography (`ISC`)

- **`lucide-solid`** (<https://lucide.dev>)
  - Copyright: Lucide Contributors
  - License: ISC License

---

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the [GNU General Public License v3.0 or later](../../LICENSE) for full terms.
