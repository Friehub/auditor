// SAFE: Uses an authorization check (userId from session) in the WHERE clause to prevent IDOR.
import { Request, Response } from 'express';

export function retrieveBasket(req: Request, res: Response) {
    const id = req.params.id;
    const userId = req.user.id;
    BasketModel.findOne({ where: { id, userId } })
        .then((basket: any) => {
            if (basket) {
                res.json(basket);
            }
        });
}
