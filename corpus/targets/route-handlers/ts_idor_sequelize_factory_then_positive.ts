// observation: User input is used directly to query an object via Sequelize without validating ownership inside a factory closure.
import { Request, Response, NextFunction } from 'express';

export function retrieveBasket() {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id;
    BasketModel.findOne({ where: { id } })
        .then((basket: any) => {
            if (basket) {
                res.json(basket);
            }
        });
  }
}
