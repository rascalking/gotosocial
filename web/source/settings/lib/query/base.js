/*
	GoToSocial
	Copyright (C) GoToSocial Authors admin@gotosocial.org
	SPDX-License-Identifier: AGPL-3.0-or-later

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

"use strict";

const { createApi, fetchBaseQuery } = require("@reduxjs/toolkit/query/react");
const { serialize: serializeForm } = require("object-to-formdata");

function instanceBasedQuery(args, api, extraOptions) {
	const state = api.getState();
	const { instance, token } = state.oauth;

	if (args.baseUrl == undefined) {
		args.baseUrl = instance;
	}

	if (args.discardEmpty) {
		if (args.body == undefined || Object.keys(args.body).length == 0) {
			return { data: null };
		}
		delete args.discardEmpty;
	}

	if (args.asForm) {
		delete args.asForm;
		args.body = serializeForm(args.body, {
			indices: true, // Array indices, for profile fields
		});
	}

	return fetchBaseQuery({
		baseUrl: args.baseUrl,
		prepareHeaders: (headers) => {
			if (token != undefined) {
				headers.set('Authorization', token);
			}
			headers.set("Accept", "application/json");
			return headers;
		},
	})(args, api, extraOptions);
}

module.exports = createApi({
	reducerPath: "api",
	baseQuery: instanceBasedQuery,
	tagTypes: ["Auth", "Blocks", "Emoji", "Reports", "Account", "InstanceRules"],
	endpoints: (build) => ({
		instance: build.query({
			query: () => ({
				url: `/api/v1/instance`
			})
		})
	})
});
