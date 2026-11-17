/**
 * v5
 *
 * @url https://github.com/SeydX/homebridge-camera-ui (original)
 * @url https://github.com/Redlah/homebridge-camera-ui-hikvision (fork)
 * @author SeydX <seydx@outlook.de>
 *
 **/
'use-strict';

import { HomebridgeCameraUI } from './src/platform.js';

export default (api) => {
  api.registerPlatform('homebridge-camera-ui-hikvision', 'CameraUI', HomebridgeCameraUI, true);
};
