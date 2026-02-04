/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import fs from 'fs';
import { execSync } from 'node:child_process';

const tag = process.env.GITHUB_REF_NAME || process.env.TAG;

if (!tag) {
    console.log('No git tag found. Skipping docs versioning.');
    process.exit(0);
}

// Accept v0.20.0 or 0.20.0
const version = tag.startsWith('v') ? tag.slice(1) : tag;

// --- Guard: skip if version already exists ---
if (fs.existsSync('./versions.json')) {
    const versions = JSON.parse(fs.readFileSync('./versions.json', 'utf8'));

    if (versions.includes(version)) {
        console.log(`Docs version ${version} already exists. Skipping.`);
        process.exit(0);
    }
}

console.log(`Creating docs version: ${version}`);

execSync(`npx docusaurus docs:version ${version}`, {
    stdio: 'inherit',
});
