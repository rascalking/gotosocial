// GoToSocial
// Copyright (C) GoToSocial Authors admin@gotosocial.org
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	apimodel "github.com/superseriousbusiness/gotosocial/internal/api/model"
	apiutil "github.com/superseriousbusiness/gotosocial/internal/api/util"
	"github.com/superseriousbusiness/gotosocial/internal/gtserror"
	"github.com/superseriousbusiness/gotosocial/internal/oauth"
)

// DomainBlocksPATCHHandler swagger:operation PATCH /api/v1/admin/domain_blocks/{id} domainBlockUpdate
//
// Updates the domain block with the given ID.
//
//			---
//			tags:
//			- admin
//
//			consumes:
//			- multipart/form-data
//
//			produces:
//			- application/json
//
//			parameters:
//			-
//				name: id
//				type: string
//				description: The id of the domain block.
//				in: path
//				required: true
//		     -
//		             name: domain
//		             in: formData
//		             description: Domain to block.
//		             type: string
//		     -
//		             name: obfuscate
//		             in: formData
//		             description: >-
//		                     Obfuscate the name of the domain when serving it publicly.
//		                     Eg., `example.org` becomes something like `ex***e.org`.
//		             type: boolean
//		     -
//		             name: public_comment
//		             in: formData
//		             description: >-
//		                     Public comment about this domain block.
//		                     This will be displayed alongside the domain block if you choose to share blocks.
//		             type: string
//		     -
//		             name: private_comment
//		             in: formData
//		             description: >-
//		                     Private comment about this domain block. Will only be shown to other admins, so this
//		                     is a useful way of internally keeping track of why a certain domain ended up blocked.
//		             type: string
//
//		     security:
//		     - OAuth2 Bearer:
//		             - admin
//
//	     responses:
//	             '200':
//	                     description: The newly updated domain block.
//	                     schema:
//	                             "$ref": "#/definitions/domainBlock"
//	             '400':
//	                     description: bad request
//	             '401':
//	                     description: unauthorized
//	             '403':
//	                     description: forbidden
//	             '404':
//	                     description: not found
//	             '406':
//	                     description: not acceptable
//	             '500':
//	                     description: internal server error
func (m *Module) DomainBlockPATCHHandler(c *gin.Context) {
	authed, err := oauth.Authed(c, true, true, true, true)
	if err != nil {
		apiutil.ErrorHandler(c, gtserror.NewErrorUnauthorized(err, err.Error()), m.processor.InstanceGetV1)
		return
	}

	if !*authed.User.Admin {
		err := fmt.Errorf("user %s not an admin", authed.User.ID)
		apiutil.ErrorHandler(c, gtserror.NewErrorForbidden(err, err.Error()), m.processor.InstanceGetV1)
		return
	}

	if _, err := apiutil.NegotiateAccept(c, apiutil.JSONAcceptHeaders...); err != nil {
		apiutil.ErrorHandler(c, gtserror.NewErrorNotAcceptable(err, err.Error()), m.processor.InstanceGetV1)
		return
	}

	domainBlockID, errWithCode := apiutil.ParseID(c.Param(apiutil.IDKey))
	if errWithCode != nil {
		apiutil.ErrorHandler(c, errWithCode, m.processor.InstanceGetV1)
		return
	}

	form, err := parseDomainBlockUpdateForm(c)
	if err != nil {
		apiutil.ErrorHandler(c, gtserror.NewErrorBadRequest(err, err.Error()), m.processor.InstanceGetV1)
		return
	}
	fmt.Printf("%+v", form)

	domainBlock, errWithCode := m.processor.Admin().DomainBlockUpdate(c.Request.Context(), authed.Account, domainBlockID, form)
	if errWithCode != nil {
		apiutil.ErrorHandler(c, errWithCode, m.processor.InstanceGetV1)
		return
	}

	c.JSON(http.StatusOK, domainBlock)
}

func parseDomainBlockUpdateForm(c *gin.Context) (*apimodel.DomainBlockUpdateRequest, error) {
	form := &apimodel.DomainBlockUpdateRequest{}
	if err := c.ShouldBind(form); err != nil {
		return nil, err
	}

	if form == nil ||
		(form.Domain == nil &&
			form.Obfuscate == nil &&
			form.PrivateComment == nil &&
			form.PublicComment == nil) {
		return nil, errors.New("empty form submitted")
	}
	return form, nil
}
