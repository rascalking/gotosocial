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

package bundb

import (
	"context"
	"net/url"

	"github.com/superseriousbusiness/gotosocial/internal/config"
	"github.com/superseriousbusiness/gotosocial/internal/db"
	"github.com/superseriousbusiness/gotosocial/internal/gtsmodel"
	"github.com/superseriousbusiness/gotosocial/internal/state"
	"github.com/superseriousbusiness/gotosocial/internal/util"
	"github.com/uptrace/bun"
)

type domainDB struct {
	db    *DB
	state *state.State
}

func (d *domainDB) CreateDomainBlock(ctx context.Context, block *gtsmodel.DomainBlock) error {
	// Normalize the domain as punycode
	var err error
	block.Domain, err = util.Punify(block.Domain)
	if err != nil {
		return err
	}

	// Attempt to store domain block in DB
	if _, err := d.db.NewInsert().
		Model(block).
		Exec(ctx); err != nil {
		return err
	}

	// Clear the domain block cache (for later reload)
	d.state.Caches.GTS.DomainBlock().Clear()

	return nil
}

func (d *domainDB) GetDomainBlock(ctx context.Context, domain string) (*gtsmodel.DomainBlock, error) {
	// Normalize the domain as punycode
	domain, err := util.Punify(domain)
	if err != nil {
		return nil, err
	}

	// Check for easy case, domain referencing *us*
	if domain == "" || domain == config.GetAccountDomain() ||
		domain == config.GetHost() {
		return nil, db.ErrNoEntries
	}

	var block gtsmodel.DomainBlock

	// Look for block matching domain in DB
	q := d.db.
		NewSelect().
		Model(&block).
		Where("? = ?", bun.Ident("domain_block.domain"), domain)
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	return &block, nil
}

func (d *domainDB) GetDomainBlocks(ctx context.Context) ([]*gtsmodel.DomainBlock, error) {
	blocks := []*gtsmodel.DomainBlock{}

	if err := d.db.
		NewSelect().
		Model(&blocks).
		Scan(ctx); err != nil {
		return nil, err
	}

	return blocks, nil
}

func (d *domainDB) GetDomainBlockByID(ctx context.Context, id string) (*gtsmodel.DomainBlock, error) {
	var block gtsmodel.DomainBlock

	q := d.db.
		NewSelect().
		Model(&block).
		Where("? = ?", bun.Ident("domain_block.id"), id)
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	return &block, nil
}

func (d *domainDB) DeleteDomainBlock(ctx context.Context, domain string) error {
	// Normalize the domain as punycode
	domain, err := util.Punify(domain)
	if err != nil {
		return err
	}

	// Attempt to delete domain block
	if _, err := d.db.NewDelete().
		Model((*gtsmodel.DomainBlock)(nil)).
		Where("? = ?", bun.Ident("domain_block.domain"), domain).
		Exec(ctx); err != nil {
		return err
	}

	// Clear the domain block cache (for later reload)
	d.state.Caches.GTS.DomainBlock().Clear()

	return nil
}

func (d *domainDB) UpdateDomainBlock(ctx context.Context, block *gtsmodel.DomainBlock) error {
	var err error

	// Normalize the domain as punycode
	block.Domain, err = util.Punify(block.Domain)
	if err != nil {
		return err
	}

	// Attempt to update domain block in DB
	if _, err := d.db.NewUpdate().
		Model(block).
		WherePK().
		Exec(ctx); err != nil {
		return err
	}

	// Clear the domain block cache (for later reload)
	d.state.Caches.GTS.DomainBlock().Clear()

	return nil
}

func (d *domainDB) IsDomainBlocked(ctx context.Context, domain string) (bool, error) {
	// Normalize the domain as punycode
	domain, err := util.Punify(domain)
	if err != nil {
		return false, err
	}

	// Check for easy case, domain referencing *us*
	if domain == "" || domain == config.GetAccountDomain() ||
		domain == config.GetHost() {
		return false, nil
	}

	// Check the cache for a domain block (hydrating the cache with callback if necessary)
	return d.state.Caches.GTS.DomainBlock().IsBlocked(domain, func() ([]string, error) {
		var domains []string

		// Scan list of all blocked domains from DB
		q := d.db.NewSelect().
			Table("domain_blocks").
			Column("domain")
		if err := q.Scan(ctx, &domains); err != nil {
			return nil, err
		}

		return domains, nil
	})
}

func (d *domainDB) AreDomainsBlocked(ctx context.Context, domains []string) (bool, error) {
	for _, domain := range domains {
		if blocked, err := d.IsDomainBlocked(ctx, domain); err != nil {
			return false, err
		} else if blocked {
			return blocked, nil
		}
	}
	return false, nil
}

func (d *domainDB) IsURIBlocked(ctx context.Context, uri *url.URL) (bool, error) {
	return d.IsDomainBlocked(ctx, uri.Hostname())
}

func (d *domainDB) AreURIsBlocked(ctx context.Context, uris []*url.URL) (bool, error) {
	for _, uri := range uris {
		if blocked, err := d.IsDomainBlocked(ctx, uri.Hostname()); err != nil {
			return false, err
		} else if blocked {
			return blocked, nil
		}
	}
	return false, nil
}
